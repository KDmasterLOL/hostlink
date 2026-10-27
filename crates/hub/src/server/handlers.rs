use super::{HubError, auth::require_operator, config::App, now};
use crate::{
    DisplayNameRequest, EnrollRequest, EnrollResponse, HostsResponse, HubInfo, InviteRequest,
    InviteResponse, MachineId, RegisteredHost, RevokeReceipt, enrollment, ssh_authorization,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::de::DeserializeOwned;

pub(super) async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}
pub(super) async fn info(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<HubInfo>, HubError> {
    require_operator(&headers, &app)?;
    Ok(Json(HubInfo {
        api_version: 2,
        management: true,
        gateways: app.config.gateways.clone(),
        execution_transport: "russh".into(),
        hosts_endpoint: "/v2/hosts".into(),
    }))
}
pub(super) async fn list_hosts(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<HostsResponse>, HubError> {
    require_operator(&headers, &app)?;
    run_blocking(move || {
        let locked = app
            .store
            .lock()
            .map_err(|_| HubError::internal("Hub state unavailable"))?;
        Ok(Json(HostsResponse {
            hosts: locked.state.hosts.into_values().collect(),
        }))
    })
    .await
}
pub(super) async fn get_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<RegisteredHost>, HubError> {
    require_operator(&headers, &app)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    run_blocking(move || {
        let locked = app
            .store
            .lock()
            .map_err(|_| HubError::internal("Hub state unavailable"))?;
        locked
            .state
            .hosts
            .get(&id)
            .cloned()
            .map(Json)
            .ok_or(HubError::NotFound)
    })
    .await
}
pub(super) async fn create_invite(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InviteResponse>), HubError> {
    require_operator(&headers, &app)?;
    let request: InviteRequest = parse_json(body)?;
    run_blocking(move || {
        enrollment::create_invite(&app, request)
            .map(|response| (StatusCode::CREATED, Json(response)))
    })
    .await
}
pub(super) async fn enroll_host(
    State(app): State<App>,
    body: Bytes,
) -> Result<(StatusCode, Json<EnrollResponse>), HubError> {
    let request: EnrollRequest = parse_json(body)?;
    run_blocking(move || {
        enrollment::enroll(&app, request).map(|response| (StatusCode::CREATED, Json(response)))
    })
    .await
}
fn parse_json<T: DeserializeOwned>(bytes: Bytes) -> Result<T, HubError> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(HubError::bad("request body is empty or exceeds 64 KiB"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| HubError::bad("request JSON is invalid or contains unknown fields"))
}
pub(super) async fn rename_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<Json<RegisteredHost>, HubError> {
    require_operator(&headers, &app)?;
    let req: DisplayNameRequest = parse_json(body)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    let name = validate_display_name(&req.display_name)?;
    run_blocking(move || {
        let mut locked = app
            .store
            .lock()
            .map_err(|_| HubError::internal("Hub state unavailable"))?;
        ensure_unique_name(&locked.state.hosts, &name, Some(&id))?;
        let host = locked.state.hosts.get_mut(&id).ok_or(HubError::NotFound)?;
        host.display_name = Some(name);
        host.updated_at = now();
        let output = host.clone();
        locked.state.audit.push(crate::state::AuditEntry {
            at: now(),
            action: "rename".into(),
            machine_id: Some(id),
        });
        locked.commit().map_err(commit_error)?;
        Ok(Json(output))
    })
    .await
}
pub(super) async fn delete_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<RevokeReceipt>, HubError> {
    require_operator(&headers, &app)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    run_blocking(move || {
        let mut locked = app
            .store
            .lock()
            .map_err(|_| HubError::internal("Hub state unavailable"))?;
        if locked.state.hosts.remove(&id).is_none() {
            return Err(HubError::NotFound);
        }
        locked.state.audit.push(crate::state::AuditEntry {
            at: now(),
            action: "revoke".into(),
            machine_id: Some(id),
        });
        locked.commit().map_err(commit_error)?;
        // The durable revocation may already be visible to the Hub lookup while an
        // earlier authorized_keys projection still admits the revoked gateway key.
        // Do not return HTTP success until the gateway projection is reconciled.
        ssh_authorization::reconcile(&app).map_err(|_| {
            HubError::Unavailable(
                "revocation committed; gateway key projection reconciliation is required".into(),
            )
        })?;
        Ok(Json(RevokeReceipt {
            revoked_new_connections: true,
            confirmed_session_terminated: false,
            remote_uninstall: false,
            authorized_key_projection: "reconciled".into(),
        }))
    })
    .await
}

async fn run_blocking<T, F>(operation: F) -> Result<T, HubError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, HubError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| HubError::internal("Hub operation failed"))?
}
pub(crate) fn validate_name(name: &str) -> Result<String, HubError> {
    let value = name.trim();
    if value.is_empty()
        || value.len() > 128
        || value != value.to_ascii_lowercase()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err(HubError::bad(
            "name must be a canonical lowercase ASCII host name",
        ));
    }
    Ok(value.to_owned())
}
pub(crate) fn validate_display_name(name: &str) -> Result<String, HubError> {
    let value = name.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(HubError::bad(
            "display name must contain 1-128 printable characters",
        ));
    }
    Ok(value.to_owned())
}
pub(crate) fn ensure_unique_name(
    hosts: &std::collections::BTreeMap<MachineId, RegisteredHost>,
    name: &str,
    except: Option<&MachineId>,
) -> Result<(), HubError> {
    if hosts
        .iter()
        .any(|(id, h)| Some(id) != except && h.name.eq_ignore_ascii_case(name))
    {
        Err(HubError::Conflict("host name already exists".into()))
    } else {
        Ok(())
    }
}
pub(crate) fn commit_error(error: crate::state::CommitError) -> HubError {
    match error {
        crate::state::CommitError::NotCommitted(_) => {
            HubError::Internal("state publication failed".into())
        }
        crate::state::CommitError::Uncertain(_) => HubError::Unavailable(
            "state publication outcome is uncertain; reconcile before retry".into(),
        ),
    }
}
