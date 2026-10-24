//! Controller-side hub configuration, secret resolution, validation, and private persistence.

use super::*;

const HUB_CONFIG_VERSION: u32 = 1;
const HUB_CONTROLLER_CONFIG_MAX_BYTES: usize = 1024 * 1024;
const HUB_CONTROLLER_TOKEN_MAX_BYTES: usize = 64 * 1024;

/// Declared effect of a native managed invocation; used for owned-resource
/// admission and target-scoped mutual exclusion, not per-host authorization.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedTargetEffect {
    /// No target mutation is permitted.
    #[default]
    ReadOnly,
    /// Only toolkit/test-run-owned files, processes and jobs may be mutated.
    RunOwned,
    /// Explicitly disposable test infobases/state may also be mutated.
    Disposable,
}

impl ManagedTargetEffect {
    /// Stable CLI/config spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::RunOwned => "run-owned",
            Self::Disposable => "disposable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One local gateway endpoint used only when an older hub omits its topology.
pub struct ControllerGateway {
    /// SSH gateway hostname/address.
    pub host: String,
    /// SSH gateway user.
    pub user: String,
    /// SSH gateway port.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
}

impl ControllerGateway {
    fn new(host: impl Into<String>, user: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            port,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Persisted controller-side hub, gateway, trust, and operator-token configuration.
pub struct HubControllerConfig {
    /// Configuration schema version.
    pub version: u32,
    /// Private controller API base URL.
    pub url: HubHttpsUrl,
    /// Optional public managed-release base URL projected by deployment policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_base_url: Option<HubHttpsUrl>,
    /// Ordered local fallback endpoints for pre-multi-edge hubs.
    pub gateways: Vec<ControllerGateway>,
    /// Optional explicit controller private-key path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
    /// Optional pinned gateway known_hosts path for legacy hub fallback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<PathBuf>,
    /// Environment-variable name holding the operator API token when no token file is configured.
    pub token_env: String,
    /// Optional private file containing the operator API token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HubControllerConfigWire {
    version: u32,
    url: HubHttpsUrl,
    #[serde(default)]
    release_base_url: Option<HubHttpsUrl>,
    #[serde(default)]
    gateways: Option<Vec<ControllerGateway>>,
    #[serde(default)]
    gateway_host: Option<String>,
    #[serde(default)]
    gateway_user: Option<String>,
    #[serde(default)]
    gateway_port: Option<u16>,
    #[serde(default)]
    identity: Option<PathBuf>,
    #[serde(default)]
    known_hosts: Option<PathBuf>,
    #[serde(default = "default_operator_token_env")]
    token_env: String,
    #[serde(default)]
    token_file: Option<PathBuf>,
    // Read legacy controller configs, validate their values, then discard
    // obsolete target-specific authorization on the next save.
    #[serde(default)]
    target_max_effects: BTreeMap<String, ManagedTargetEffect>,
}

impl<'de> Deserialize<'de> for HubControllerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let wire = HubControllerConfigWire::deserialize(deserializer)?;
        let legacy_present = wire.gateway_host.is_some()
            || wire.gateway_user.is_some()
            || wire.gateway_port.is_some();
        let gateways = match (wire.gateways, legacy_present) {
            (Some(_), true) => {
                return Err(D::Error::custom(
                    "controller config must use either gateways[] or legacy gateway fields, not both",
                ));
            }
            (Some(gateways), false) => gateways,
            (None, _) => vec![ControllerGateway::new(
                wire.gateway_host
                    .ok_or_else(|| D::Error::missing_field("gateways"))?,
                wire.gateway_user
                    .ok_or_else(|| D::Error::missing_field("gateway_user"))?,
                wire.gateway_port.unwrap_or_else(default_ssh_port),
            )],
        };
        let mut seen_machine_ids = std::collections::HashSet::new();
        for (machine_id, _effect) in wire.target_max_effects {
            if !is_valid_machine_id(&machine_id) {
                return Err(D::Error::custom(
                    "managed target machine id must contain only ASCII letters, digits, '.', '-' or '_'",
                ));
            }
            let normalized = normalized_machine_id(&machine_id);
            if !seen_machine_ids.insert(normalized.clone()) {
                return Err(D::Error::custom(format!(
                    "managed target max-effect contains duplicate machine identity {normalized:?}"
                )));
            }
        }
        Ok(Self {
            version: wire.version,
            url: wire.url,
            release_base_url: wire.release_base_url,
            gateways,
            identity: wire.identity,
            known_hosts: wire.known_hosts,
            token_env: wire.token_env,
            token_file: wire.token_file,
        })
    }
}

fn default_ssh_port() -> u16 {
    22
}
fn default_operator_token_env() -> String {
    "ONEC_HUB_OPERATOR_TOKEN".to_owned()
}

impl HubControllerConfig {
    /// Creates version-current controller configuration with one legacy-hub fallback endpoint.
    pub fn new(
        url: impl AsRef<str>,
        gateway_host: impl Into<String>,
        gateway_user: impl Into<String>,
    ) -> AppResult<Self> {
        Ok(Self {
            version: HUB_CONFIG_VERSION,
            url: HubHttpsUrl::parse(url.as_ref())?,
            release_base_url: None,
            gateways: vec![ControllerGateway::new(gateway_host, gateway_user, 22)],
            identity: None,
            known_hosts: None,
            token_env: default_operator_token_env(),
            token_file: None,
        })
    }

    /// Loads and validates configuration from [`hub_config_path`].
    pub fn load() -> AppResult<Self> {
        Self::load_from(hub_config_path()?)
    }

    /// Loads configuration when the default path exists, otherwise returns `None`.
    pub fn load_optional() -> AppResult<Option<Self>> {
        let path = hub_config_path()?;
        if !path.exists() {
            return Ok(None);
        }
        Self::load_from(path).map(Some)
    }

    /// Loads bounded strict JSON from an explicit path and resolves relative paths.
    pub fn load_from(path: impl AsRef<Path>) -> AppResult<Self> {
        let path = path.as_ref();
        let bytes = onec_core::read_file_bounded(path, HUB_CONTROLLER_CONFIG_MAX_BYTES)
            .map_err(|source| io_error(path, source))?;
        let mut config: Self = serde_json::from_slice(&bytes)
            .map_err(|source| crate::json_error(path.to_path_buf(), source))?;
        if config.version != HUB_CONFIG_VERSION {
            return Err(crate::invalid_config(format!(
                "unsupported onec-access config version {} in {}; expected {}",
                config.version,
                path.display(),
                HUB_CONFIG_VERSION
            )));
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_optional_path(&mut config.identity, base);
        resolve_optional_path(&mut config.known_hosts, base);
        resolve_optional_path(&mut config.token_file, base);
        config.validate()?;
        Ok(config)
    }

    /// Atomically persists configuration to [`hub_config_path`] with private-file permissions.
    pub fn save(&self) -> AppResult<()> {
        self.save_to(hub_config_path()?)
    }

    /// Atomically persists validated configuration to an explicit private file.
    pub fn save_to(&self, path: impl AsRef<Path>) -> AppResult<()> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|source| crate::json_error(path.to_path_buf(), source))?;
        onec_core::write_private_file_atomically(path, &data)
            .map_err(|source| io_error(path, source))
    }

    /// Validates schema, fallback endpoints and operator-token source.
    pub fn validate(&self) -> AppResult<()> {
        if self.version != HUB_CONFIG_VERSION {
            return Err(crate::invalid_config(format!(
                "unsupported onec-hub controller config version {}",
                self.version
            )));
        }
        if self.gateways.is_empty()
            || self.gateways.iter().any(|gateway| {
                gateway.host.trim().is_empty()
                    || gateway.user.trim().is_empty()
                    || gateway.port == 0
            })
        {
            return Err(crate::invalid_config(
                "onec-access requires non-empty fallback gateway host/user and non-zero port"
                    .to_owned(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        if self
            .gateways
            .iter()
            .any(|gateway| !seen.insert((gateway.host.to_ascii_lowercase(), gateway.port)))
        {
            return Err(crate::invalid_config(
                "onec-access fallback gateways must not contain duplicate host/port endpoints"
                    .to_owned(),
            ));
        }
        if self.token_env.trim().is_empty() && self.token_file.is_none() {
            return Err(crate::invalid_config(
                "a onec-hub operator token source is required".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn token(&self) -> AppResult<SecretString> {
        let token = if let Some(path) = self.token_file.as_deref() {
            onec_core::validate_private_file(path).map_err(crate::private_path_error)?;
            let bytes = onec_core::read_file_bounded(path, HUB_CONTROLLER_TOKEN_MAX_BYTES)
                .map_err(|source| io_error(path, source))?;
            std::str::from_utf8(&bytes)
                .map_err(|error| {
                    crate::invalid_config(format!(
                        "onec-hub operator token file {} must be UTF-8: {error}",
                        path.display()
                    ))
                })?
                .trim()
                .to_owned()
        } else {
            env::var(&self.token_env).map_err(|_| {
                crate::invalid_config(format!(
                    "environment variable {:?} containing the onec-hub operator token is not set",
                    self.token_env
                ))
            })?
        };
        if token.trim().len() < 32 {
            return Err(crate::invalid_config(
                "onec-hub operator token must contain at least 32 characters".to_owned(),
            ));
        }
        Ok(token.into())
    }
}

fn normalized_machine_id(machine_id: &str) -> String {
    machine_id.trim().to_ascii_lowercase()
}

fn is_valid_machine_id(machine_id: &str) -> bool {
    let machine_id = machine_id.trim();
    !machine_id.is_empty()
        && machine_id.len() <= 128
        && machine_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn resolve_optional_path(path: &mut Option<PathBuf>, base: &Path) {
    if let Some(value) = path
        && value.is_relative()
    {
        *value = base.join(&*value);
    }
}

/// Returns the controller config path from `ONEC_ACCESS_CONFIG` or OS-native config root.
pub fn hub_config_path() -> AppResult<PathBuf> {
    config_path()
}
