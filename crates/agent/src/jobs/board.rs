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

pub(super) fn router(store: &JobStore, address: std::net::SocketAddr, root: &Path) -> Router {
    let root = root.to_owned();
    let api = ApiBuilder::new(Router::new())
        .register("commands", store.backend.clone())
        .build();
    Router::new()
        .nest("/api/v1", api)
        .route("/new", get(|| async { Html(include_str!("new.html")) }))
        .fallback_service(ServeUI::new())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(move |request, next| {
            guard(request, next, address, root.clone())
        }))
}

async fn guard(
    mut request: Request<axum::body::Body>,
    next: Next,
    address: std::net::SocketAddr,
    root: PathBuf,
) -> Result<Response, StatusCode> {
    // Reject DNS rebinding and cross-site browser requests. Non-browser local
    // clients may omit Origin; browsers performing a cross-origin PUT cannot.
    let expected = address.to_string();
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    if host != Some(expected.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Some(origin) = request.headers().get(header::ORIGIN)
        && origin.to_str().ok() != Some(format!("http://{expected}").as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if request.method() == axum::http::Method::PUT {
        // The upstream API accepts task lifecycle headers. A submission must
        // not fabricate a terminal/running task or request unbounded retries.
        for name in [
            "x-task-status",
            "x-task-attempt",
            "x-task-done-at",
            "x-task-lock-at",
            "x-task-lock-by",
        ] {
            if request.headers().contains_key(name) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        match request.headers().get("x-task-max-attempts") {
            None => {
                request
                    .headers_mut()
                    .insert("x-task-max-attempts", "3".parse().expect("static header"));
            }
            Some(value)
                if value
                    .to_str()
                    .ok()
                    .and_then(|v| v.parse::<u8>().ok())
                    .is_some_and(|v| (1..=3).contains(&v)) => {}
            _ => return Err(StatusCode::BAD_REQUEST),
        }
        let lock = database::try_update_lock(&root).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let response = next.run(request).await;
        lock.unlock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(response);
    }
    Ok(next.run(request).await)
}
