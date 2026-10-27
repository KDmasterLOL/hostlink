use super::{App, handlers};
use crate::ssh_authorization;
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};

pub fn router(service: super::HubService) -> Router {
    let app = service.app;
    Router::new()
        .route("/healthz", get(handlers::health))
        .route("/v2/info", get(handlers::info))
        .route("/v2/hosts", get(handlers::list_hosts))
        .route(
            "/v2/hosts/{machine_id}",
            get(handlers::get_host).delete(handlers::delete_host),
        )
        .route(
            "/v2/hosts/{machine_id}/display-name",
            patch(handlers::rename_host),
        )
        .route("/v2/invites", post(handlers::create_invite))
        .route("/v2/enroll", post(handlers::enroll_host))
        .route(
            "/internal/v2/ssh/authorized-key",
            post(ssh_authorization::lookup),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            bounded_concurrency,
        ))
        .with_state(app)
}

pub(super) async fn bounded_concurrency(
    State(app): State<App>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = app.concurrency.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Hub request capacity reached",
        )
            .into_response();
    };
    let response = next.run(request).await;
    drop(permit);
    response
}
