use super::config::App;
use axum::{
    Json,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde::Serialize;

#[derive(Debug)]
pub enum HubError {
    Bad(String),
    Unauthorized,
    NotFound,
    Conflict(String),
    Unavailable(String),
    Internal(String),
}
impl HubError {
    pub(crate) fn bad(s: impl Into<String>) -> Self {
        Self::Bad(s.into())
    }
    pub(crate) fn internal(s: impl Into<String>) -> Self {
        Self::Internal(s.into())
    }
}
impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bad(s) | Self::Conflict(s) | Self::Unavailable(s) | Self::Internal(s) => {
                f.write_str(s)
            }
            Self::Unauthorized => f.write_str("authorization failed"),
            Self::NotFound => f.write_str("resource not found"),
        }
    }
}
impl std::error::Error for HubError {}
impl IntoResponse for HubError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Bad(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authorization failed".into(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".into(),
            ),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            Self::Unavailable(m) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "reconciliation_required",
                m,
            ),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "request failed".into(),
            ),
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response()
    }
}
#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

pub(super) fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
pub(super) fn require_operator(headers: &HeaderMap, app: &App) -> Result<(), HubError> {
    if authorized(headers, app.config.operator_token.expose_secret()) {
        Ok(())
    } else {
        Err(HubError::Unauthorized)
    }
}
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
