//! Hub configuration loading, normalization, validation, and environment-secret lookup.

use super::*;

const HUB_SERVER_CONFIG_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub(super) struct HubConfig {
    pub(super) version: u32,
    #[serde(default = "default_listen")]
    pub(super) listen: String,
    pub(super) public_url: HubHttpsUrl,
    pub(super) gateways: Vec<onec_hub::GatewayEndpoint>,
    /// Restricted SSH account used by controllers to open direct-tcpip channels
    /// to agent reverse listeners. Legacy configs may omit it and keep using
    /// controller-local single-gateway fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) controller_ssh_user: Option<String>,
    /// Legacy primary operator public key kept for backward-compatible hub configs and
    /// enrollment clients that only understand one controller identity.
    #[serde(default)]
    pub(super) operator_ssh_public_key: String,
    /// Ordered controller public keys installed into each user-mode Windows sshd
    /// authorized_keys. The first key is the legacy primary identity.
    #[serde(default)]
    pub(super) operator_ssh_public_keys: Vec<String>,
    pub(super) authorized_keys: PathBuf,
    pub(super) state_file: PathBuf,
    #[serde(default = "default_operator_token_env")]
    pub(super) operator_token_env: String,
    #[serde(default = "default_agent_secret_key_env")]
    pub(super) agent_secret_key_env: String,
    #[serde(default)]
    pub(super) ssh_lookup_token_env: Option<String>,
    #[serde(default = "default_probe_gateway_ports_locally")]
    pub(super) probe_gateway_ports_locally: bool,
    #[serde(default = "default_port_from")]
    pub(super) port_from: u16,
    #[serde(default = "default_port_to")]
    pub(super) port_to: u16,
    #[serde(default)]
    pub(super) reserved_ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HubConfigWire {
    version: u32,
    #[serde(default = "default_listen")]
    listen: String,
    public_url: HubHttpsUrl,
    #[serde(default)]
    gateways: Vec<onec_hub::GatewayEndpoint>,
    #[serde(default)]
    controller_ssh_user: Option<String>,
    #[serde(default)]
    gateway_host: Option<String>,
    #[serde(default)]
    agent_ssh_user: Option<String>,
    #[serde(default)]
    gateway_ssh_port: Option<u16>,
    #[serde(default)]
    gateway_host_public_key: Option<String>,
    #[serde(default)]
    operator_ssh_public_key: String,
    #[serde(default)]
    operator_ssh_public_keys: Vec<String>,
    authorized_keys: PathBuf,
    state_file: PathBuf,
    #[serde(default = "default_operator_token_env")]
    operator_token_env: String,
    #[serde(default = "default_agent_secret_key_env")]
    agent_secret_key_env: String,
    #[serde(default)]
    ssh_lookup_token_env: Option<String>,
    #[serde(default = "default_probe_gateway_ports_locally")]
    probe_gateway_ports_locally: bool,
    #[serde(default = "default_port_from")]
    port_from: u16,
    #[serde(default = "default_port_to")]
    port_to: u16,
    #[serde(default)]
    reserved_ports: Vec<u16>,
}

impl<'de> Deserialize<'de> for HubConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        Self::try_from(HubConfigWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl TryFrom<HubConfigWire> for HubConfig {
    type Error = io::Error;

    fn try_from(wire: HubConfigWire) -> Result<Self, Self::Error> {
        let has_legacy = wire.gateway_host.is_some()
            || wire.agent_ssh_user.is_some()
            || wire.gateway_ssh_port.is_some()
            || wire.gateway_host_public_key.is_some();
        if !wire.gateways.is_empty() && has_legacy {
            return Err(invalid(
                "hub config must use either gateways[] or legacy single-gateway fields, not both",
            ));
        }
        let gateways = if wire.gateways.is_empty() {
            let host = wire
                .gateway_host
                .ok_or_else(|| invalid("missing gateway_host"))?;
            let user = wire
                .agent_ssh_user
                .ok_or_else(|| invalid("missing agent_ssh_user"))?;
            let host_public_key = wire
                .gateway_host_public_key
                .ok_or_else(|| invalid("missing gateway_host_public_key"))?;
            vec![onec_hub::GatewayEndpoint {
                host,
                user,
                port: wire.gateway_ssh_port.unwrap_or_else(default_ssh_port),
                host_public_key,
            }]
        } else {
            wire.gateways
        };
        let config = Self {
            version: wire.version,
            listen: wire.listen,
            public_url: wire.public_url,
            gateways,
            controller_ssh_user: wire.controller_ssh_user,
            operator_ssh_public_key: wire.operator_ssh_public_key,
            operator_ssh_public_keys: wire.operator_ssh_public_keys,
            authorized_keys: wire.authorized_keys,
            state_file: wire.state_file,
            operator_token_env: wire.operator_token_env,
            agent_secret_key_env: wire.agent_secret_key_env,
            ssh_lookup_token_env: wire.ssh_lookup_token_env,
            probe_gateway_ports_locally: wire.probe_gateway_ports_locally,
            port_from: wire.port_from,
            port_to: wire.port_to,
            reserved_ports: wire.reserved_ports,
        };
        config.validate()?;
        Ok(config)
    }
}

fn default_listen() -> String {
    "127.0.0.1:27400".to_owned()
}
fn default_ssh_port() -> u16 {
    22
}
fn default_operator_token_env() -> String {
    "ONEC_HUB_OPERATOR_TOKEN".to_owned()
}
fn default_agent_secret_key_env() -> String {
    "ONEC_HUB_AGENT_SECRET_KEY".to_owned()
}
fn default_probe_gateway_ports_locally() -> bool {
    true
}
fn default_port_from() -> u16 {
    41000
}
fn default_port_to() -> u16 {
    41999
}

impl HubConfig {
    pub(super) fn load(path: &Path) -> io::Result<Self> {
        let wire: HubConfigWire =
            onec_core::read_json_file_bounded(path, HUB_SERVER_CONFIG_MAX_BYTES)?;
        let mut config = Self::try_from(wire)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.authorized_keys.is_relative() {
            config.authorized_keys = base.join(&config.authorized_keys);
        }
        if config.state_file.is_relative() {
            config.state_file = base.join(&config.state_file);
        }
        Ok(config)
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(invalid(format!(
                "unsupported hub config version {}; expected {CONFIG_VERSION}",
                self.version
            )));
        }
        let listen = self
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|error| {
                invalid(format!("invalid listen address {:?}: {error}", self.listen))
            })?;
        if !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("onec-hub must listen on loopback behind HTTPS, got {listen}"),
            ));
        }
        if listen.port() == 0 {
            return Err(invalid("hub listen port must be non-zero"));
        }
        if self.authorized_keys.as_os_str().is_empty() || self.state_file.as_os_str().is_empty() {
            return Err(invalid("authorized_keys and state_file paths are required"));
        }
        if self.gateways.is_empty()
            || self.operator_token_env.trim().is_empty()
            || self.agent_secret_key_env.trim().is_empty()
            || self
                .ssh_lookup_token_env
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
        {
            return Err(invalid(
                "at least one gateway and hub secret env names are required",
            ));
        }
        if self
            .controller_ssh_user
            .as_deref()
            .is_some_and(|user| user.trim().is_empty())
        {
            return Err(invalid("controller_ssh_user must not be empty"));
        }
        if self.gateways.len() > 1 && self.controller_ssh_user.is_none() {
            return Err(invalid(
                "multi-edge gateways require controller_ssh_user for controller routing",
            ));
        }
        let mut gateway_addresses = std::collections::BTreeSet::new();
        for gateway in &self.gateways {
            gateway.validate_fields().map_err(invalid)?;
            normalize_public_key(&gateway.host_public_key)?;
            // Agent-side SshTunnelConfig uses this same endpoint identity.
            // Checking raw spelling here could accept a Hub configuration
            // whose issued agent.json is then rejected at agent startup.
            if !gateway_addresses.insert((gateway.host.trim().to_ascii_lowercase(), gateway.port)) {
                return Err(invalid(
                    "gateways must not contain duplicate host/port entries",
                ));
            }
        }
        self.normalized_operator_ssh_public_keys()?;
        if self.port_from < 1024 || self.port_from > self.port_to {
            return Err(invalid("invalid SSH or remote-port range"));
        }
        if self
            .reserved_ports
            .iter()
            .any(|port| *port < self.port_from || *port > self.port_to)
        {
            return Err(invalid(
                "reserved_ports entries must stay inside the remote-port range",
            ));
        }
        let mut unique_reserved = self.reserved_ports.clone();
        unique_reserved.sort_unstable();
        unique_reserved.dedup();
        if unique_reserved.len() != self.reserved_ports.len() {
            return Err(invalid("reserved_ports must not contain duplicates"));
        }
        Ok(())
    }

    pub(super) fn controller_gateways(&self) -> Option<Vec<onec_hub::GatewayEndpoint>> {
        let user = self.controller_ssh_user.as_deref()?.trim();
        if user.is_empty() {
            return None;
        }
        Some(
            self.gateways
                .iter()
                .cloned()
                .map(|mut gateway| {
                    gateway.user = user.to_owned();
                    gateway
                })
                .collect(),
        )
    }

    pub(super) fn normalized_operator_ssh_public_keys(&self) -> io::Result<Vec<String>> {
        let mut keys = self
            .operator_ssh_public_keys
            .iter()
            .map(|key| normalize_public_key(key))
            .collect::<io::Result<Vec<_>>>()?;
        let legacy = self.operator_ssh_public_key.trim();

        if keys.is_empty() {
            if legacy.is_empty() {
                return Err(invalid("at least one operator SSH public key is required"));
            }
            keys.push(normalize_public_key(legacy)?);
        } else if !legacy.is_empty() {
            let primary = normalize_public_key(legacy)?;
            if keys.first() != Some(&primary) {
                return Err(invalid(
                    "operator_ssh_public_key must match the first operator_ssh_public_keys entry",
                ));
            }
        }

        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != keys.len() {
            return Err(invalid(
                "operator_ssh_public_keys must not contain duplicates",
            ));
        }
        Ok(keys)
    }

    pub(super) fn operator_token(&self) -> io::Result<SecretString> {
        secret_from_env(&self.operator_token_env, "hub operator token")
    }

    pub(super) fn agent_secret_key(&self) -> io::Result<SecretString> {
        secret_from_env(&self.agent_secret_key_env, "hub agent-secret key")
    }

    pub(super) fn ssh_lookup_token(&self) -> io::Result<Option<SecretString>> {
        self.ssh_lookup_token_env
            .as_deref()
            .map(|name| secret_from_env(name, "hub SSH lookup token"))
            .transpose()
    }
}

fn secret_from_env(name: &str, description: &str) -> io::Result<SecretString> {
    let value = env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "environment variable {:?} containing the {description} is not set",
                name
            ),
        )
    })?;
    let value = value.trim().to_owned();
    if value.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{description} must contain at least 32 characters"),
        ));
    }
    Ok(value.into())
}

#[cfg(test)]
mod schema_tests {
    use super::*;

    #[test]
    fn hub_rejects_gateway_names_that_agent_considers_the_same_endpoint() {
        for second in [" GATEWAY.EXAMPLE.TEST ", "gateway.example.test"] {
            let mut value = minimal_config_json();
            let object = value.as_object_mut().expect("config object");
            object.remove("gateway_host");
            object.remove("agent_ssh_user");
            object.remove("gateway_host_public_key");
            object.insert("controller_ssh_user".into(), serde_json::json!("operator"));
            object.insert(
                "gateways".into(),
                serde_json::json!([
                    {
                        "host": "gateway.example.test", "user": "agent", "port": 22,
                        "host_public_key": test_key("gateway-a")
                    },
                    {
                        "host": second, "user": "agent", "port": 22,
                        "host_public_key": test_key("gateway-b")
                    }
                ]),
            );
            let error = serde_json::from_value::<HubConfig>(value)
                .expect_err("duplicate after agent normalization");
            assert!(error.to_string().contains("duplicate host/port"), "{error}");
        }
    }

    #[test]
    fn gateway_identity_allows_distinct_ports_on_same_normalized_host() {
        let mut value = minimal_config_json();
        let object = value.as_object_mut().expect("config object");
        object.remove("gateway_host");
        object.remove("agent_ssh_user");
        object.remove("gateway_host_public_key");
        object.insert("controller_ssh_user".into(), serde_json::json!("operator"));
        object.insert(
            "gateways".into(),
            serde_json::json!([
                {
                    "host": "Gateway.Example.Test", "user": "agent", "port": 22,
                    "host_public_key": test_key("gateway-a")
                },
                {
                    "host": " gateway.example.test ", "user": "agent", "port": 2222,
                    "host_public_key": test_key("gateway-b")
                }
            ]),
        );
        let config = serde_json::from_value::<HubConfig>(value)
            .expect("different ports are distinct endpoints");
        assert_eq!(config.gateways.len(), 2);
    }

    fn test_key(seed: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use sha2::{Digest as _, Sha256};
        let bytes = Sha256::digest(seed.as_bytes());
        let mut blob = Vec::with_capacity(51);
        blob.extend_from_slice(&11_u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&bytes);
        format!("ssh-ed25519 {} fixture-{seed}", STANDARD.encode(blob))
    }

    fn minimal_config_json() -> serde_json::Value {
        serde_json::json!({
            "version": CONFIG_VERSION,
            "public_url": "https://hub.example.test",
            "gateway_host": "gateway.example.test",
            "agent_ssh_user": "agent",
            "gateway_host_public_key": test_key("gateway"),
            "operator_ssh_public_key": test_key("operator"),
            "authorized_keys": "authorized_keys",
            "state_file": "state.json"
        })
    }

    #[test]
    fn hub_server_public_url_is_typed_at_json_ingress() {
        let mut value = minimal_config_json();
        value["public_url"] = serde_json::json!(["https://", "user@", "hub.example.test"].concat());
        let error = serde_json::from_value::<HubConfig>(value).expect_err("userinfo must fail");
        assert!(
            error.to_string().contains("must not contain username"),
            "{error}"
        );
    }

    #[test]
    fn hub_server_config_rejects_unknown_fields() {
        let mut value = minimal_config_json();
        value
            .as_object_mut()
            .unwrap()
            .insert("gatway_host".to_owned(), serde_json::json!("typo"));
        let error = serde_json::from_value::<HubConfig>(value).expect_err("unknown field");
        let message = error.to_string();
        assert!(message.contains("unknown field"), "{message}");
        assert!(message.contains("gatway_host"), "{message}");
    }

    #[test]
    fn hub_static_port_policy_is_enforced_during_json_deserialization() {
        let mut value = minimal_config_json();
        value["listen"] = serde_json::json!("127.0.0.1:0");
        let error = serde_json::from_value::<HubConfig>(value).expect_err("zero listener port");
        assert!(
            error.to_string().contains("listen port must be non-zero"),
            "{error}"
        );

        let mut value = minimal_config_json();
        value["port_from"] = serde_json::json!(0);
        let error = serde_json::from_value::<HubConfig>(value).expect_err("zero remote port range");
        assert!(
            error
                .to_string()
                .contains("invalid SSH or remote-port range"),
            "{error}"
        );
    }

    #[test]
    fn hub_load_preserves_policy_error_category() {
        let dir = tempfile::tempdir().expect("config directory");
        let path = dir.path().join("hub.json");
        let mut value = minimal_config_json();
        value["listen"] = serde_json::json!("0.0.0.0:27400");
        fs::write(&path, serde_json::to_vec(&value).expect("hub JSON")).expect("hub config");

        let error = HubConfig::load(&path).expect_err("public listener must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("loopback behind HTTPS"),
            "{error}"
        );
    }

    #[test]
    fn regression_inv_108_hub_server_config_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hub.json");
        fs::write(&path, vec![b' '; HUB_SERVER_CONFIG_MAX_BYTES + 1]).expect("oversized config");

        let error = HubConfig::load(&path).expect_err("oversized config must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn older_hub_server_config_still_uses_current_defaults() {
        let config =
            serde_json::from_value::<HubConfig>(minimal_config_json()).expect("supported config");
        assert_eq!(config.listen, "127.0.0.1:27400");
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].host, "gateway.example.test");
        assert_eq!(config.gateways[0].user, "agent");
        assert_eq!(config.gateways[0].port, 22);
        assert!(config.controller_ssh_user.is_none());
        assert_eq!(config.operator_token_env, "ONEC_HUB_OPERATOR_TOKEN");
        assert_eq!(config.agent_secret_key_env, "ONEC_HUB_AGENT_SECRET_KEY");
        assert!(config.probe_gateway_ports_locally);
        assert!(config.operator_ssh_public_keys.is_empty());
    }

    #[test]
    fn canonical_gateway_list_serializes_without_legacy_fields() {
        let mut value = minimal_config_json();
        let object = value.as_object_mut().expect("config object");
        object.remove("gateway_host");
        object.remove("agent_ssh_user");
        object.remove("gateway_host_public_key");
        object.insert(
            "gateways".to_owned(),
            serde_json::json!([
                {
                    "host": "gateway-a.example.test",
                    "user": "agent",
                    "port": 22,
                    "host_public_key": test_key("gateway-a")
                },
                {
                    "host": "gateway-b.example.test",
                    "user": "agent",
                    "port": 2222,
                    "host_public_key": test_key("gateway-b")
                }
            ]),
        );
        object.insert(
            "controller_ssh_user".to_owned(),
            serde_json::json!("operator"),
        );
        let config = serde_json::from_value::<HubConfig>(value).expect("canonical config");
        assert_eq!(config.gateways.len(), 2);
        assert_eq!(config.controller_ssh_user.as_deref(), Some("operator"));
        let serialized = serde_json::to_value(&config).expect("serialize config");
        assert!(serialized.get("gateways").is_some());
        assert!(serialized.get("gateway_host").is_none());
        assert!(serialized.get("agent_ssh_user").is_none());
        assert!(serialized.get("gateway_ssh_port").is_none());
        assert!(serialized.get("gateway_host_public_key").is_none());
    }

    #[test]
    fn controller_routes_project_access_user_without_changing_agent_routes() {
        let mut value = minimal_config_json();
        let object = value.as_object_mut().expect("config object");
        object.remove("gateway_host");
        object.remove("agent_ssh_user");
        object.remove("gateway_host_public_key");
        object.insert(
            "gateways".to_owned(),
            serde_json::json!([{
                "host": "gateway.example.test",
                "user": "agent",
                "host_public_key": test_key("gateway")
            }]),
        );
        object.insert(
            "controller_ssh_user".to_owned(),
            serde_json::json!("operator"),
        );
        let config = serde_json::from_value::<HubConfig>(value).expect("canonical config");
        let routes = config.controller_gateways().expect("controller routes");
        assert_eq!(routes[0].user, "operator");
        assert_eq!(config.gateways[0].user, "agent");
    }

    #[test]
    fn config_rejects_mixed_legacy_and_multi_edge_gateway_schema() {
        let mut value = minimal_config_json();
        value.as_object_mut().expect("config object").insert(
            "gateways".to_owned(),
            serde_json::json!([{
                "host": "gateway-b.example.test",
                "user": "agent",
                "host_public_key": test_key("gateway-b")
            }]),
        );
        let error = serde_json::from_value::<HubConfig>(value).expect_err("mixed schema");
        assert!(error.to_string().contains("either gateways[] or legacy"));
    }
}
