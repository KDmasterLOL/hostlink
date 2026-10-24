//! Operator bearer-token extraction and constant-time authorization.

use super::*;
use axum::http::HeaderMap;

pub(super) fn require_operator(headers: &HeaderMap, app: &App) -> io::Result<()> {
    let Some(token) = bearer_token(headers) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "missing operator token",
        ));
    };
    if !hostlink_core::constant_time_str_eq(token, app.operator_token.expose_secret()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid operator token",
        ));
    }
    Ok(())
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
