//! HTTP response and request-body helpers for the Axum server boundary.

use axum::{
    body::Bytes,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use std::io;

pub(crate) type ApiResponse = Response;

pub(crate) fn json<T: Serialize>(status: StatusCode, value: &T) -> ApiResponse {
    no_store((status, axum::Json(value)).into_response())
}

pub(crate) fn text(status: StatusCode, body: impl Into<String>) -> ApiResponse {
    no_store((status, body.into()).into_response())
}

fn no_store(mut response: ApiResponse) -> ApiResponse {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn json_error(status: StatusCode, code: &str, message: &str) -> ApiResponse {
    json(
        status,
        &serde_json::json!({"error": code, "message": message}),
    )
}

pub(crate) fn parse_json_body<T: DeserializeOwned>(body: &Bytes) -> io::Result<T> {
    serde_json::from_slice(body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid JSON request: {error}"),
        )
    })
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn internal_error(error: io::Error) -> ApiResponse {
    eprintln!("onec-hub request failed: {error}");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "hub request failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::CACHE_CONTROL;

    #[test]
    fn application_json_responses_are_no_store() {
        let response = json(StatusCode::OK, &serde_json::json!({"ok": true}));
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
}
