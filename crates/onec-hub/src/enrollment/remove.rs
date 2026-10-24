//! Agent revocation against authoritative durable hub state.

use super::super::*;
use axum::http::{HeaderMap, StatusCode};

pub(crate) fn remove_agent_request(
    headers: &HeaderMap,
    app: &App,
    machine_id: &str,
) -> io::Result<ApiResponse> {
    if let Err(error) = require_operator(headers, app) {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &error.to_string(),
        ));
    }
    if let Err(error) = validate_machine_id(machine_id) {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &error.to_string(),
        ));
    }

    let mut writer = app.lock_state_writer()?;
    let state = writer.state_mut();
    let Some(record) = state.agents.get(machine_id).cloned() else {
        drop(writer);
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent is not enrolled",
        ));
    };

    state.agents.remove(machine_id);
    if let Err(error) = writer.commit(true) {
        if error.committed() {
            eprintln!("onec-hub revocation committed with degraded projection: {error}");
            return Ok(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "reconciliation_required",
                "revocation was committed; hub projection reconciliation is required",
            ));
        }
        if error.uncertain() {
            eprintln!("onec-hub revocation state commit is uncertain: {error}");
            return Ok(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "state_commit_uncertain",
                "revocation state publication outcome is uncertain; restart and reconciliation are required",
            ));
        }
        return Err(error.into_io());
    }

    hub_audit(
        "agent.removed",
        HubAuditFields {
            machine_id: Some(record.machine_id.clone()),
            agent_name: Some(record.name.clone()),
            remote_port: Some(record.remote_port),
            ..HubAuditFields::default()
        },
    );
    Ok(json(
        StatusCode::OK,
        &serde_json::json!({
            "removed": true,
            "machine_id": machine_id,
            "name": record.name,
        }),
    ))
}
