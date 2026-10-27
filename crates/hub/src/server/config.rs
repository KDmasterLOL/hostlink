use super::HubError;
use crate::{GatewayEndpoint, state::StateStore, validate_ed25519_public_key};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
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
        axum::serve(listener, super::router(self)).await
    }
}

pub(super) fn validate_runtime_config(config: &HubConfig) -> Result<(), HubError> {
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
