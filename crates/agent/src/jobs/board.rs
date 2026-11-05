use super::*;
use apalis_board_api::{
    framework::{ApiBuilder, RegisterRoute},
    ui::ServeUI,
};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, Response},
    routing::get,
};
use tower_http::validate_request::ValidateRequestHeaderLayer;

pub(super) fn router(store: &JobStore, address: std::net::SocketAddr) -> Router {
    let api = ApiBuilder::new(Router::new())
        .register("commands", store.backend.clone())
        .build();
    Router::new()
        .nest("/api/v1", api)
        .route(
            "/new",
            get(|| async {
                (
                    [(
                        "x-hostlink-command-timeout-max",
                        MAX_COMMAND_TIMEOUT_SECONDS.to_string(),
                    )],
                    Html(include_str!("new.html")),
                )
            }),
        )
        .fallback_service(ServeUI::new())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(move |request, next| {
            origin_guard(request, next, address)
        }))
        // Require the exact loopback Host before dispatching any Board route.
        .layer(
            ValidateRequestHeaderLayer::has_header_value(
                header::HOST.as_str(),
                &address.to_string(),
            )
            .expect("static HTTP Host header name"),
        )
}

async fn origin_guard(
    request: Request<axum::body::Body>,
    next: Next,
    address: std::net::SocketAddr,
) -> Result<Response, StatusCode> {
    // Host is validated by Tower HTTP. Reject cross-origin browser requests;
    // non-browser local clients may omit Origin.
    if let Some(origin) = request.headers().get(header::ORIGIN)
        && origin.to_str().ok() != Some(format!("http://{address}").as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod form_tests {
    #[test]
    fn operator_form_submits_one_attempt() {
        assert!(include_str!("new.html").contains("'x-task-max-attempts':'1'"));
    }
}
