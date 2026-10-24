//! SSH public-key lookup for sshd AuthorizedKeysCommand integration.

use super::super::*;
use axum::http::{HeaderMap, StatusCode};

pub(crate) fn ssh_authorized_key_lookup(
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    app: &App,
) -> io::Result<ApiResponse> {
    let Some(expected_token) = app.ssh_lookup_token.as_ref() else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "SSH lookup is not configured",
        ));
    };
    let Some(token) = bearer_token(headers) else {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing SSH lookup token",
        ));
    };
    if !hostlink_core::constant_time_str_eq(token, expected_token.expose_secret()) {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid SSH lookup token",
        ));
    }
    let input: SshAuthorizedKeyLookupRequest = match parse_json_body(body) {
        Ok(input) => input,
        Err(error) => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &error.to_string(),
            ));
        }
    };
    let state = HubState::load(&app.config.state_file)?;
    match lookup_authorized_key(&state, &input.key_type, &input.key_blob) {
        Ok(Some(line)) => Ok(text(StatusCode::OK, format!("{line}\n"))),
        Ok(None) => Ok(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "SSH key is not enrolled",
        )),
        Err(error) => Ok(json_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &error.to_string(),
        )),
    }
}

pub(crate) fn lookup_authorized_key(
    state: &HubState,
    key_type: &str,
    key_blob: &str,
) -> io::Result<Option<String>> {
    if key_type != "ssh-ed25519"
        || key_blob.is_empty()
        || !key_blob
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(invalid("invalid Ed25519 key payload"));
    }
    let offered = normalize_public_key(&format!("{key_type} {key_blob}"))?;
    state
        .agents
        .values()
        .find(|record| {
            normalize_public_key(&record.ssh_public_key).ok().as_deref() == Some(offered.as_str())
        })
        .map(authorized_key_line)
        .transpose()
}
