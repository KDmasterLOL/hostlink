//! One-use enrollment against authoritative durable hub state.

use super::super::*;
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};

pub(crate) fn enroll_request(
    headers: &HeaderMap,
    body: &Bytes,
    app: &App,
) -> io::Result<ApiResponse> {
    let Some(token) = bearer_token(headers) else {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing enrollment token",
        ));
    };
    let digest = token_digest(token);
    let input: EnrollRequest = match parse_json_body(body) {
        Ok(input) => input,
        Err(error) => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &error.to_string(),
            ));
        }
    };
    if let Err(error) = validate_enrollment(&input) {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &error.to_string(),
        ));
    }
    let now = Utc::now().timestamp();

    let mut writer = app.lock_state_writer()?;
    let state = writer.state_mut();
    state.remove_expired_invites(now);
    let Some(invite) = state.invitations.get(&digest).cloned() else {
        drop(writer);
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_invite",
            "enrollment token is invalid or expired",
        ));
    };
    if invite.used || invite.expires_at <= now {
        drop(writer);
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_invite",
            "enrollment token is invalid or expired",
        ));
    }

    let existing = state.agents.get(&input.machine_id).cloned();
    let remote_port = if let Some(existing) = &existing {
        existing.remote_port
    } else {
        allocate_port(state, &app.config)?
    };
    let assigned_name = assign_name(
        state,
        &input.machine_id,
        invite.name_hint.as_deref().unwrap_or(&input.name),
    )?;
    let control_credential_nonce = random_control_credential_nonce()?;
    let record = AgentRecord {
        id: existing
            .as_ref()
            .map(|value| value.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        machine_id: input.machine_id.clone(),
        name: assigned_name,
        display_name: existing
            .as_ref()
            .and_then(|agent| agent.display_name.clone()),
        hostname: input.hostname,
        username: input.username.filter(|value| !value.trim().is_empty()),
        os: input.os,
        arch: input.arch,
        agent_version: input.agent_version,
        transport: input.transport,
        persistence_mode: input.persistence_mode.or_else(|| {
            existing
                .as_ref()
                .and_then(|record| record.persistence_mode.clone())
        }),
        remote_port,
        ssh_public_key: normalize_public_key(&input.ssh_public_key)?,
        ssh_host_public_key: input
            .ssh_host_public_key
            .as_deref()
            .map(normalize_public_key)
            .transpose()?,
        control_credential_nonce: Some(control_credential_nonce),
        enrolled_at: existing
            .as_ref()
            .map(|value| value.enrolled_at)
            .unwrap_or(now),
        updated_at: now,
    };

    state.version = STATE_VERSION;
    state
        .agents
        .insert(record.machine_id.clone(), record.clone());
    if let Some(invite) = state.invitations.get_mut(&digest) {
        invite.used = true;
    }
    if let Err(error) = writer.commit(true) {
        return Ok(write_enrollment_commit_error(error));
    }

    hub_audit(
        "agent.enrolled",
        HubAuditFields {
            machine_id: Some(record.machine_id.clone()),
            agent_name: Some(record.name.clone()),
            remote_port: Some(record.remote_port),
            reenroll: Some(existing.is_some()),
            ..HubAuditFields::default()
        },
    );
    let control_secret = derive_control_secret(
        &app.agent_secret_key,
        &record.machine_id,
        record.control_credential_nonce.as_deref(),
    )?;
    let operator_ssh_public_keys = app.config.normalized_operator_ssh_public_keys()?;
    let primary_gateway = app
        .config
        .gateways
        .first()
        .expect("validated hub config has at least one gateway");
    Ok(json(
        StatusCode::OK,
        &EnrollResponse {
            id: record.id,
            machine_id: record.machine_id,
            name: record.name,
            remote_port: record.remote_port,
            control_secret,
            gateways: app.config.gateways.clone(),
            gateway_host: primary_gateway.host.clone(),
            gateway_ssh_port: primary_gateway.port,
            agent_ssh_user: primary_gateway.user.clone(),
            gateway_host_public_key: primary_gateway.host_public_key.clone(),
            operator_ssh_public_key: operator_ssh_public_keys[0].clone(),
            operator_ssh_public_keys,
        },
    ))
}

pub(crate) fn write_enrollment_commit_error(error: StateCommitError) -> ApiResponse {
    if error.committed() {
        eprintln!("onec-hub enrollment committed with degraded projection: {error}");
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "reconciliation_required",
            "enrollment was committed; hub projection reconciliation is required",
        );
    }
    if error.uncertain() {
        eprintln!("onec-hub enrollment state commit is uncertain: {error}");
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "state_commit_uncertain",
            "enrollment state publication outcome is uncertain; restart and reconciliation are required",
        );
    }
    internal_error(error.into_io())
}
