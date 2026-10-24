//! Native Tokio/Axum listener and HTTP application boundary.

use super::*;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State, rejection::BytesRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::Response,
    routing::{delete, get, patch, post},
};
use std::{
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::TcpListener;
use tower::{
    ServiceBuilder, limit::GlobalConcurrencyLimitLayer, load_shed::LoadShedLayer,
    timeout::TimeoutLayer,
};
use tower_http::{limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer};

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
static OVERLOAD_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn prepare_server_state(app: &App) -> io::Result<()> {
    app.reconcile_authoritative_state()
}

pub(super) async fn serve(app: App) -> io::Result<()> {
    prepare_server_state(&app)?;
    let address = app.config.listen.clone();
    eprintln!(
        "HostLink Hub listening on {} (public {})",
        address, app.config.public_url
    );
    serve_async(Arc::new(app), address).await
}

async fn serve_async(app: Arc<App>, address: String) -> io::Result<()> {
    let listener = TcpListener::bind(&address).await?;
    axum::serve(listener, router(app)).await
}

pub(super) fn router(app: Arc<App>) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/info", get(info))
        .route("/v1/invites", post(create_invite))
        .route("/v1/enroll", post(enroll))
        .route("/internal/v1/ssh/authorized-key", post(ssh_authorized_key))
        .route("/v1/agents", get(list_agents))
        .route(
            "/v1/agents/{machine_id}/control-credential",
            get(control_credential),
        )
        .route(
            "/v1/agents/{machine_id}/display-name",
            patch(change_display_name),
        )
        .route("/v1/agents/{machine_id}", delete(remove_agent))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(app)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));
    with_request_middleware(routes, MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT)
}

pub(super) fn with_request_middleware(
    router: Router,
    concurrency: usize,
    timeout: Duration,
) -> Router {
    router
        .layer(
            ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    map_service_error,
                ))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(concurrency))
                .layer(TimeoutLayer::new(timeout)),
        )
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

async fn map_service_error(error: Box<dyn Error + Send + Sync>) -> Response {
    if error
        .downcast_ref::<tower::load_shed::error::Overloaded>()
        .is_some()
    {
        let count = OVERLOAD_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        hub_audit(
            "request.overloaded",
            HubAuditFields {
                overload_count: Some(count),
                ..HubAuditFields::default()
            },
        );
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "hub request capacity is full",
        );
    }
    if error
        .downcast_ref::<tower::timeout::error::Elapsed>()
        .is_some()
    {
        return json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timeout",
            "hub request timed out",
        );
    }
    eprintln!("HostLink Hub HTTP middleware failed: {error}");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "hub request failed",
    )
}

async fn healthz() -> Response {
    json(StatusCode::OK, &serde_json::json!({"ok": true}))
}

async fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "not_found", "endpoint not found")
}

async fn info(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if let Err(error) = require_operator(&headers, &app) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized", &error.to_string());
    }
    let controller_gateways = app.config.controller_gateways();
    let mut capabilities = vec![
        "agents.secret-free-inventory-v1",
        "agents.control-credential-v1",
    ];
    if controller_gateways.is_some() {
        capabilities.push("gateway.multi-edge-v1");
    }
    json(
        StatusCode::OK,
        &serde_json::json!({
            "public_url": app.config.public_url,
            "gateways": controller_gateways.unwrap_or_default(),
            "capabilities": capabilities
        }),
    )
}

async fn create_invite(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if let Err(error) = require_operator(&headers, &app) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized", &error.to_string());
    }
    let body = match request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let input: InviteRequest = match parse_json_body(&body) {
        Ok(input) => input,
        Err(error) => {
            return json_error(StatusCode::BAD_REQUEST, "bad_request", &error.to_string());
        }
    };
    if let Some(name) = input.name.as_deref()
        && let Err(error) = validate_identifier("name", name, 128)
    {
        return json_error(StatusCode::BAD_REQUEST, "bad_request", &error.to_string());
    }
    let result = (|| -> io::Result<Response> {
        let ttl = input.ttl_seconds.clamp(60, 86_400);
        let now = Utc::now().timestamp();
        let token = random_secret()?;
        let digest = token_digest(token.expose_secret());
        let mut writer = app.lock_state_writer()?;
        let state = writer.state_mut();
        state.remove_expired_invites(now);
        let expires_at = now + ttl as i64;
        let name_hint = input.name.filter(|value| !value.trim().is_empty());
        state.invitations.insert(
            digest,
            Invitation {
                created_at: now,
                expires_at,
                used: false,
                name_hint,
            },
        );
        if let Err(error) = writer.commit(false) {
            return Ok(invite_commit_error(error));
        }
        hub_audit(
            "invite.created",
            HubAuditFields {
                expires_at: Some(expires_at),
                ..HubAuditFields::default()
            },
        );
        Ok(json(
            StatusCode::CREATED,
            &InviteResponse {
                token,
                expires_at,
                public_url: app.config.public_url.clone(),
            },
        ))
    })();
    result.unwrap_or_else(internal_error)
}

pub(super) fn invite_commit_error(error: StateCommitError) -> Response {
    if error.uncertain() {
        eprintln!("HostLink Hub invitation state commit is uncertain: {error}");
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "state_commit_uncertain",
            "invitation state publication outcome is uncertain; retry only after hub restart/reconciliation",
        );
    }
    internal_error(error.into_io())
}

async fn enroll(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    enroll_request(&headers, &body, &app).unwrap_or_else(internal_error)
}

async fn ssh_authorized_key(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    ssh_authorized_key_lookup(&headers, &body, &app).unwrap_or_else(internal_error)
}

async fn list_agents(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if let Err(error) = require_operator(&headers, &app) {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized", &error.to_string());
    }
    let result = (|| -> io::Result<Response> {
        let state = HubState::load(&app.config.state_file)?;
        let agents = state
            .agents
            .values()
            .map(|record| AgentView { record })
            .collect();
        Ok(json(StatusCode::OK, &AgentsResponse { agents }))
    })();
    result.unwrap_or_else(internal_error)
}

async fn control_credential(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
) -> Response {
    get_control_credential(&headers, &app, &machine_id).unwrap_or_else(internal_error)
}

async fn change_display_name(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match request_body(body) {
        Ok(body) => body,
        Err(response) => return *response,
    };
    display_name::update_display_name_request(&headers, &app, &machine_id, &body)
        .unwrap_or_else(internal_error)
}

async fn remove_agent(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(machine_id): Path<String>,
) -> Response {
    remove_agent_request(&headers, &app, &machine_id).unwrap_or_else(internal_error)
}

fn request_body(body: Result<Bytes, BytesRejection>) -> Result<Bytes, Box<Response>> {
    body.map_err(|_| {
        Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "request body is invalid or too large",
        ))
    })
}
