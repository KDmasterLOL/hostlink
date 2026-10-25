use crate::{enrollment, ssh_authorization, state::StateStore, *};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct HubConfig {
    pub listen: SocketAddr,
    pub public_url: String,
    pub state_root: PathBuf,
    pub authorized_keys: PathBuf,
    pub gateways: Vec<GatewayEndpoint>,
    pub operator_ssh_public_keys: Vec<String>,
    pub operator_token: SecretString,
    pub gateway_lookup_token: SecretString,
    pub port_from: u16,
    pub port_to: u16,
    pub reserved_ports: BTreeSet<u16>,
}

#[derive(Clone)]
pub(crate) struct App {
    pub config: Arc<HubConfig>,
    pub store: Arc<StateStore>,
    pub concurrency: Arc<Semaphore>,
}

impl HubConfig {
    pub fn load(path: &FsPath) -> Result<Self, HubError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FileConfig {
            version: u32,
            listen: String,
            public_url: String,
            state_root: PathBuf,
            authorized_keys: PathBuf,
            gateways: Vec<GatewayEndpoint>,
            operator_ssh_public_keys: Vec<String>,
            #[serde(default = "default_env_operator")]
            operator_token_env: String,
            #[serde(default = "default_env_gateway")]
            gateway_lookup_token_env: String,
            port_from: u16,
            port_to: u16,
            #[serde(default)]
            reserved_ports: BTreeSet<u16>,
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| HubError::internal("config unavailable"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024
        {
            return Err(HubError::bad("config must be a bounded regular file"));
        }
        let file = fs::File::open(path).map_err(|_| HubError::internal("config unavailable"))?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HubError::internal("config unavailable"))?;
        if bytes.len() > 1024 * 1024 {
            return Err(HubError::bad("config exceeds size limit"));
        }
        let wire: FileConfig =
            serde_json::from_slice(&bytes).map_err(|_| HubError::bad("config JSON is invalid"))?;
        if wire.version != 2 {
            return Err(HubError::bad("unsupported config version"));
        }
        let listen: SocketAddr = wire
            .listen
            .parse()
            .map_err(|_| HubError::bad("listen must be a loopback socket address"))?;
        if !listen.ip().is_loopback() || listen.port() == 0 {
            return Err(HubError::bad(
                "Hub listener must bind a nonzero loopback address",
            ));
        }
        validate_public_url(&wire.public_url)?;
        if wire.gateways.is_empty() || wire.gateways.len() > 16 {
            return Err(HubError::bad(
                "one to sixteen approved gateways are required",
            ));
        }
        for gateway in &wire.gateways {
            gateway.validate().map_err(HubError::bad)?;
        }
        if wire.operator_ssh_public_keys.is_empty() || wire.operator_ssh_public_keys.len() > 32 {
            return Err(HubError::bad(
                "one to thirty-two operator SSH keys are required",
            ));
        }
        for key in &wire.operator_ssh_public_keys {
            validate_ed25519_public_key(key).map_err(HubError::bad)?;
        }
        if wire.port_from == 0 || wire.port_from > wire.port_to {
            return Err(HubError::bad("invalid reverse port range"));
        }
        let parent = path.parent().unwrap_or(FsPath::new("."));
        let state_root = if wire.state_root.is_absolute() {
            wire.state_root
        } else {
            parent.join(wire.state_root)
        };
        let authorized_keys = if wire.authorized_keys.is_absolute() {
            wire.authorized_keys
        } else {
            parent.join(wire.authorized_keys)
        };
        let operator_token = std::env::var(&wire.operator_token_env)
            .map_err(|_| HubError::bad("operator token environment variable is missing"))?;
        let gateway_lookup_token = std::env::var(&wire.gateway_lookup_token_env)
            .map_err(|_| HubError::bad("gateway lookup token environment variable is missing"))?;
        if operator_token.len() < 32
            || gateway_lookup_token.len() < 32
            || operator_token.len() > 4096
            || gateway_lookup_token.len() > 4096
            || operator_token == gateway_lookup_token
        {
            return Err(HubError::bad(
                "operator and gateway tokens must be distinct secrets of at least 32 bytes",
            ));
        }
        Ok(Self {
            listen,
            public_url: wire.public_url,
            state_root,
            authorized_keys,
            gateways: wire.gateways,
            operator_ssh_public_keys: wire.operator_ssh_public_keys,
            operator_token: SecretString::from(operator_token),
            gateway_lookup_token: SecretString::from(gateway_lookup_token),
            port_from: wire.port_from,
            port_to: wire.port_to,
            reserved_ports: wire.reserved_ports,
        })
    }
}
fn default_env_operator() -> String {
    "HOSTLINK_HUB_OPERATOR_TOKEN".into()
}
fn default_env_gateway() -> String {
    "HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN".into()
}

pub struct HubService {
    pub(crate) app: App,
}
impl HubService {
    pub fn new(config: HubConfig) -> Result<Self, HubError> {
        if !config.listen.ip().is_loopback() || config.listen.port() == 0 {
            return Err(HubError::bad("Hub listener must be loopback-only"));
        }
        validate_runtime_config(&config)?;
        // A distinct projection file is mandatory for side-by-side operation
        // with the installed legacy Hub. Never overwrite its authorized_keys.
        if config
            .authorized_keys
            .file_name()
            .and_then(|name| name.to_str())
            != Some("hostlink-v2-authorized_keys")
        {
            return Err(HubError::bad(
                "Hub v2 requires a dedicated hostlink-v2-authorized_keys projection file",
            ));
        }
        if config.state_root.file_name().and_then(|s| s.to_str()) != Some("hostlink-hub-v2") {
            return Err(HubError::bad(
                "state root must use the isolated hostlink-hub-v2 namespace",
            ));
        }
        let store = StateStore::open(&config.state_root)
            .map_err(|_| HubError::bad("unsafe or inaccessible private state root"))?;
        let current = store
            .lock()
            .map_err(|_| HubError::bad("invalid or inaccessible Hub state"))?;
        if current.state.hosts.values().any(|host| {
            host.remote_port < config.port_from
                || host.remote_port > config.port_to
                || config.reserved_ports.contains(&host.remote_port)
        }) {
            return Err(HubError::bad(
                "configured reverse port range conflicts with registered hosts",
            ));
        }
        drop(current);
        Ok(Self {
            app: App {
                config: Arc::new(config),
                store: Arc::new(store),
                concurrency: Arc::new(Semaphore::new(128)),
            },
        })
    }
    pub async fn serve(self) -> Result<(), std::io::Error> {
        let listener = tokio::net::TcpListener::bind(self.app.config.listen).await?;
        axum::serve(listener, router(self)).await
    }
}

fn validate_runtime_config(config: &HubConfig) -> Result<(), HubError> {
    validate_public_url(&config.public_url)?;
    if config.gateways.is_empty() || config.gateways.len() > 16 {
        return Err(HubError::bad(
            "one to sixteen approved gateways are required",
        ));
    }
    let mut gateway_routes = std::collections::BTreeSet::new();
    for gateway in &config.gateways {
        gateway.validate().map_err(HubError::bad)?;
        if !gateway_routes.insert((
            gateway.host.to_ascii_lowercase(),
            gateway.port,
            gateway.user.clone(),
        )) {
            return Err(HubError::bad("duplicate gateway route"));
        }
    }
    if config.operator_ssh_public_keys.is_empty() || config.operator_ssh_public_keys.len() > 32 {
        return Err(HubError::bad(
            "one to thirty-two operator SSH keys are required",
        ));
    }
    for key in &config.operator_ssh_public_keys {
        validate_ed25519_public_key(key).map_err(HubError::bad)?;
    }
    if config.operator_token.expose_secret().len() < 32
        || config.gateway_lookup_token.expose_secret().len() < 32
        || config.operator_token.expose_secret().len() > 4096
        || config.gateway_lookup_token.expose_secret().len() > 4096
        || config.operator_token.expose_secret() == config.gateway_lookup_token.expose_secret()
    {
        return Err(HubError::bad(
            "operator and gateway tokens must be distinct secrets of at least 32 bytes",
        ));
    }
    if config.port_from == 0 || config.port_from > config.port_to {
        return Err(HubError::bad("invalid reverse port range"));
    }
    Ok(())
}

fn validate_public_url(value: &str) -> Result<(), HubError> {
    if value.len() > 2048 {
        return Err(HubError::bad("Hub public URL is too long"));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| HubError::bad("Hub public URL must be a valid HTTPS origin"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(HubError::bad(
            "Hub public URL must be an HTTPS origin without credentials, path, query or fragment",
        ));
    }
    Ok(())
}

pub fn router(service: HubService) -> Router {
    let app = service.app;
    Router::new()
        .route("/healthz", get(health))
        .route("/v2/info", get(info))
        .route("/v2/hosts", get(list_hosts))
        .route("/v2/hosts/{machine_id}", get(get_host).delete(delete_host))
        .route("/v2/hosts/{machine_id}/display-name", patch(rename_host))
        .route("/v2/invites", post(create_invite))
        .route("/v2/enroll", post(enroll_host))
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

async fn bounded_concurrency(State(app): State<App>, request: Request, next: Next) -> Response {
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

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
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
fn require_operator(headers: &HeaderMap, app: &App) -> Result<(), HubError> {
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
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}
async fn info(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, HubError> {
    require_operator(&headers, &app)?;
    Ok(Json(
        serde_json::json!({"api_version":2,"management":true,"gateways":app.config.gateways,"execution_transport":"russh","hosts_endpoint":"/v2/hosts"}),
    ))
}
async fn list_hosts(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<HostsResponse>, HubError> {
    require_operator(&headers, &app)?;
    let locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    Ok(Json(HostsResponse {
        hosts: locked.state.hosts.into_values().collect(),
    }))
}
#[derive(Serialize)]
struct HostsResponse {
    hosts: Vec<RegisteredHost>,
}
async fn get_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<RegisteredHost>, HubError> {
    require_operator(&headers, &app)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    let locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    locked
        .state
        .hosts
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(HubError::NotFound)
}
async fn create_invite(
    State(app): State<App>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<InviteResponse>), HubError> {
    require_operator(&headers, &app)?;
    let request: InviteRequest = parse_json(body)?;
    enrollment::create_invite(&app, request).map(|response| (StatusCode::CREATED, Json(response)))
}
async fn enroll_host(
    State(app): State<App>,
    body: Bytes,
) -> Result<(StatusCode, Json<EnrollResponse>), HubError> {
    let request: EnrollRequest = parse_json(body)?;
    enrollment::enroll(&app, request).map(|response| (StatusCode::CREATED, Json(response)))
}
fn parse_json<T: for<'de> Deserialize<'de>>(bytes: Bytes) -> Result<T, HubError> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(HubError::bad("request body is empty or exceeds 64 KiB"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| HubError::bad("request JSON is invalid or contains unknown fields"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayNameRequest {
    display_name: String,
}
async fn rename_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<Json<RegisteredHost>, HubError> {
    require_operator(&headers, &app)?;
    let req: DisplayNameRequest = parse_json(body)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    let name = validate_display_name(&req.display_name)?;
    let mut locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    ensure_unique_name(&locked.state.hosts, &name, Some(&id))?;
    let host = locked.state.hosts.get_mut(&id).ok_or(HubError::NotFound)?;
    host.display_name = Some(name);
    host.updated_at = now();
    let output = host.clone();
    locked.state.audit.push(crate::state::AuditEntry {
        at: now(),
        action: "rename".into(),
        machine_id: Some(id),
    });
    locked.commit().map_err(commit_error)?;
    Ok(Json(output))
}
#[derive(Serialize)]
struct RevokeResponse {
    revoked_new_connections: bool,
    confirmed_session_terminated: bool,
    remote_uninstall: bool,
    authorized_key_projection: &'static str,
}
async fn delete_host(
    State(app): State<App>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Result<Json<RevokeResponse>, HubError> {
    require_operator(&headers, &app)?;
    let id = MachineId::parse(raw).map_err(HubError::bad)?;
    let mut locked = app
        .store
        .lock()
        .map_err(|_| HubError::internal("Hub state unavailable"))?;
    if locked.state.hosts.remove(&id).is_none() {
        return Err(HubError::NotFound);
    }
    locked.state.audit.push(crate::state::AuditEntry {
        at: now(),
        action: "revoke".into(),
        machine_id: Some(id),
    });
    locked.commit().map_err(commit_error)?;
    // The durable revocation may already be visible to the Hub lookup while an
    // earlier authorized_keys projection still admits the revoked gateway key.
    // Do not return HTTP success until the gateway projection is reconciled.
    ssh_authorization::reconcile(&app).map_err(|_| {
        HubError::Unavailable(
            "revocation committed; gateway key projection reconciliation is required".into(),
        )
    })?;
    Ok(Json(RevokeResponse {
        revoked_new_connections: true,
        confirmed_session_terminated: false,
        remote_uninstall: false,
        authorized_key_projection: "reconciled",
    }))
}
pub(crate) fn validate_name(name: &str) -> Result<String, HubError> {
    let value = name.trim();
    if value.is_empty()
        || value.len() > 128
        || value != value.to_ascii_lowercase()
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err(HubError::bad(
            "name must be a canonical lowercase ASCII host name",
        ));
    }
    Ok(value.to_owned())
}
pub(crate) fn validate_display_name(name: &str) -> Result<String, HubError> {
    let value = name.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(HubError::bad(
            "display name must contain 1-128 printable characters",
        ));
    }
    Ok(value.to_owned())
}
pub(crate) fn ensure_unique_name(
    hosts: &std::collections::BTreeMap<MachineId, RegisteredHost>,
    name: &str,
    except: Option<&MachineId>,
) -> Result<(), HubError> {
    if hosts
        .iter()
        .any(|(id, h)| Some(id) != except && h.name.eq_ignore_ascii_case(name))
    {
        Err(HubError::Conflict("host name already exists".into()))
    } else {
        Ok(())
    }
}
pub(crate) fn commit_error(error: crate::state::CommitError) -> HubError {
    match error {
        crate::state::CommitError::NotCommitted(_) => {
            HubError::Internal("state publication failed".into())
        }
        crate::state::CommitError::Uncertain(_) => HubError::Unavailable(
            "state publication outcome is uncertain; reconcile before retry".into(),
        ),
    }
}
