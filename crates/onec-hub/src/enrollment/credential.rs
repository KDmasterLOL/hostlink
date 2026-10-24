//! Exact per-agent control-credential retrieval for authenticated controllers.

use super::super::*;
use axum::http::{HeaderMap, StatusCode};

pub(crate) fn get_control_credential(
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

    let state = HubState::load(&app.config.state_file)?;
    let Some(record) = state.agents.get(machine_id) else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent is not enrolled",
        ));
    };
    let control_secret = derive_control_secret(
        &app.agent_secret_key,
        &record.machine_id,
        record.control_credential_nonce.as_deref(),
    )?;
    Ok(json(
        StatusCode::OK,
        &ControlCredentialResponse {
            machine_id: record.machine_id.clone(),
            control_credential_nonce: record.control_credential_nonce.clone(),
            control_secret,
        },
    ))
}
