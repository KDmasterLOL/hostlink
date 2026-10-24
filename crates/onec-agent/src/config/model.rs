//! Persisted agent/SSH configuration data model and serde defaults.

use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Persisted resident-agent configuration.
pub struct AgentConfig {
    /// Configuration schema version.
    pub(super) version: u32,
    /// Logical agent name advertised to controllers.
    pub(super) name: String,
    /// Loopback-only control listener address.
    #[serde(default = "default_listen")]
    pub(super) listen: SocketAddr,
    /// Environment-variable name used for the control secret when no secret file is configured.
    #[serde(default = "default_secret_env")]
    pub(super) secret_env: String,
    /// Optional private file containing the control secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) secret_file: Option<PathBuf>,
    /// Optional durable jobs root; otherwise the OS-native default is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) jobs_dir: Option<PathBuf>,
    /// Optional administrator-pinned approved native suite policy digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_suite_policy_sha256: Option<String>,
    /// Installer-owned directories prepended to the resident process PATH.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) path_prepend: Vec<PathBuf>,
    /// Optional managed reverse-SSH tunnel configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh: Option<SshTunnelConfig>,
    /// Optional external user-mode sshd configuration exposed behind the reverse tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ssh_server: Option<SshServerConfig>,
    /// Optional embedded russh target server. Mutually exclusive with `ssh_server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) embedded_ssh_server: Option<EmbeddedSshServerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentConfigWire {
    version: u32,
    name: String,
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    #[serde(default = "default_secret_env")]
    secret_env: String,
    #[serde(default)]
    secret_file: Option<PathBuf>,
    #[serde(default)]
    jobs_dir: Option<PathBuf>,
    #[serde(default)]
    native_suite_policy_sha256: Option<String>,
    #[serde(default)]
    path_prepend: Vec<PathBuf>,
    #[serde(default)]
    ssh: Option<SshTunnelConfig>,
    #[serde(default)]
    ssh_server: Option<SshServerConfig>,
    #[serde(default)]
    embedded_ssh_server: Option<EmbeddedSshServerConfig>,
}

impl<'de> Deserialize<'de> for AgentConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        Self::try_from(AgentConfigWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl AgentConfig {
    /// Returns the logical agent name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the loopback control listener address.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns the environment variable configured as the control-secret source.
    pub fn secret_env(&self) -> &str {
        &self.secret_env
    }

    /// Returns installer-owned directories applied to the resident process PATH.
    pub fn path_prepend(&self) -> &[PathBuf] {
        &self.path_prepend
    }

    /// Returns the optional reverse-SSH tunnel configuration.
    pub fn ssh(&self) -> Option<&SshTunnelConfig> {
        self.ssh.as_ref()
    }

    /// Returns the optional external user-mode sshd configuration.
    pub fn ssh_server(&self) -> Option<&SshServerConfig> {
        self.ssh_server.as_ref()
    }

    /// Returns the optional embedded target SSH server configuration.
    pub fn embedded_ssh_server(&self) -> Option<&EmbeddedSshServerConfig> {
        self.embedded_ssh_server.as_ref()
    }
}

impl AgentConfigWire {
    pub(super) fn resolve_relative_paths(&mut self, base: &Path) {
        resolve_optional_path(&mut self.secret_file, base);
        resolve_optional_path(&mut self.jobs_dir, base);
        for path in &mut self.path_prepend {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        if let Some(ssh) = &mut self.ssh {
            resolve_optional_path(&mut ssh.identity, base);
            resolve_optional_path(&mut ssh.known_hosts, base);
            for gateway in &mut ssh.gateways {
                if let Some(proxy) = &mut gateway.tls_proxy
                    && proxy.program.is_relative()
                {
                    proxy.program = base.join(&proxy.program);
                }
            }
        }
        if let Some(server) = &mut self.ssh_server {
            if server.program.is_relative() {
                server.program = base.join(&server.program);
            }
            if server.config.is_relative() {
                server.config = base.join(&server.config);
            }
        }
        if let Some(server) = &mut self.embedded_ssh_server {
            if server.host_key.is_relative() {
                server.host_key = base.join(&server.host_key);
            }
            if server.authorized_keys.is_relative() {
                server.authorized_keys = base.join(&server.authorized_keys);
            }
        }
    }
}

impl TryFrom<AgentConfigWire> for AgentConfig {
    type Error = io::Error;

    fn try_from(wire: AgentConfigWire) -> Result<Self, Self::Error> {
        let config = Self {
            version: wire.version,
            name: wire.name,
            listen: wire.listen,
            secret_env: wire.secret_env,
            secret_file: wire.secret_file,
            jobs_dir: wire.jobs_dir,
            native_suite_policy_sha256: wire.native_suite_policy_sha256,
            path_prepend: wire.path_prepend,
            ssh: wire.ssh,
            ssh_server: wire.ssh_server,
            embedded_ssh_server: wire.embedded_ssh_server,
        };
        config.validate_static()?;
        Ok(config)
    }
}

fn resolve_optional_path(path: &mut Option<PathBuf>, base: &Path) {
    if let Some(value) = path
        && value.is_relative()
    {
        *value = base.join(&*value);
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 27391))
}

fn default_secret_env() -> String {
    "ONEC_AGENT_SECRET".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// Embedded russh server configuration backed by installer-owned persistent key files.
pub struct EmbeddedSshServerConfig {
    /// SSH username accepted for enrolled controller public keys.
    pub user: String,
    /// Persistent Ed25519 host private key path.
    pub host_key: PathBuf,
    /// Authorized enrolled controller public keys path.
    pub authorized_keys: PathBuf,
    /// Loopback port exposed behind the managed reverse tunnel.
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// User-mode sshd process configuration.
pub struct SshServerConfig {
    /// Exact sshd executable path.
    pub program: PathBuf,
    /// Exact sshd configuration file.
    pub config: PathBuf,
    /// Loopback port on which sshd must listen.
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// Optional TLS byte-stream helper used before the in-process SSH handshake.
pub struct SshTlsProxyConfig {
    /// Exact proxy executable path.
    pub program: PathBuf,
    /// TLS SNI server name.
    pub server_name: String,
    /// Optional ALPN protocol advertised by the TLS proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One approved reverse-SSH gateway endpoint.
pub struct SshGatewayEndpoint {
    /// Managed gateway hostname/address.
    pub host: String,
    /// Gateway SSH user.
    pub user: String,
    /// Gateway SSH port.
    pub port: u16,
    /// Optional endpoint-local TLS wrapper for reaching the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_proxy: Option<SshTlsProxyConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Fail-closed managed in-process reverse-SSH tunnel configuration.
pub struct SshTunnelConfig {
    /// Legacy external SSH client path retained only for backward-compatible deserialization.
    #[serde(skip_serializing)]
    pub program: Option<PathBuf>,
    /// Ordered approved gateway endpoints.
    pub gateways: Vec<SshGatewayEndpoint>,
    /// Reverse-forward port exposed on gateway loopback.
    pub remote_port: u16,
    /// Explicit private-key path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
    /// Pinned known-hosts file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts: Option<PathBuf>,
    /// Delay before retrying a failed/closed tunnel.
    #[serde(default = "default_reconnect_seconds")]
    pub reconnect_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshTunnelConfigWire {
    #[serde(default)]
    program: Option<PathBuf>,
    #[serde(default)]
    gateways: Option<Vec<SshGatewayEndpoint>>,
    #[serde(default)]
    gateway_host: Option<String>,
    #[serde(default)]
    gateway_user: Option<String>,
    #[serde(default)]
    gateway_port: Option<u16>,
    remote_port: u16,
    #[serde(default)]
    identity: Option<PathBuf>,
    #[serde(default)]
    known_hosts: Option<PathBuf>,
    #[serde(default)]
    tls_proxy: Option<SshTlsProxyConfig>,
    #[serde(default = "default_reconnect_seconds")]
    reconnect_seconds: u64,
    #[serde(default, rename = "mode")]
    _retired_mode: Option<String>,
    #[serde(default, rename = "host_key")]
    _retired_host_key: Option<String>,
}

impl<'de> Deserialize<'de> for SshTunnelConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let wire = SshTunnelConfigWire::deserialize(deserializer)?;
        let legacy_present = wire.gateway_host.is_some()
            || wire.gateway_user.is_some()
            || wire.gateway_port.is_some()
            || wire.tls_proxy.is_some();
        let gateways = match wire.gateways {
            Some(_) if legacy_present => {
                return Err(D::Error::custom(
                    "ssh config must use either gateways[] or legacy gateway fields, not both",
                ));
            }
            Some(gateways) => gateways,
            None => vec![SshGatewayEndpoint {
                host: wire
                    .gateway_host
                    .ok_or_else(|| D::Error::missing_field("gateway_host"))?,
                user: wire
                    .gateway_user
                    .ok_or_else(|| D::Error::missing_field("gateway_user"))?,
                port: wire.gateway_port.unwrap_or_else(default_ssh_port),
                tls_proxy: wire.tls_proxy,
            }],
        };
        Ok(Self {
            program: wire.program,
            gateways,
            remote_port: wire.remote_port,
            identity: wire.identity,
            known_hosts: wire.known_hosts,
            reconnect_seconds: wire.reconnect_seconds,
        })
    }
}

fn default_ssh_port() -> u16 {
    22
}

fn default_reconnect_seconds() -> u64 {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_unknown<T>(json: &str, field: &str)
    where
        T: for<'de> Deserialize<'de> + std::fmt::Debug,
    {
        let error = serde_json::from_str::<T>(json).expect_err("unknown field must fail");
        let message = error.to_string();
        assert!(
            message.contains("unknown field") && message.contains(field),
            "{message}"
        );
    }

    #[test]
    fn owned_agent_config_objects_reject_unknown_fields() {
        assert_unknown::<AgentConfig>(
            r#"{
                "version": 1,
                "name": "agent",
                "lissten": "127.0.0.1:27391"
            }"#,
            "lissten",
        );
        assert_unknown::<EmbeddedSshServerConfig>(
            r#"{
                "user": "managed-user",
                "host_key": "ssh_host_ed25519_key",
                "authorized_keys": "sshd_authorized_keys",
                "port": 2222,
                "prt": 2223
            }"#,
            "prt",
        );
        assert_unknown::<SshServerConfig>(
            r#"{
                "program": "sshd",
                "config": "sshd_config",
                "port": 22,
                "prt": 2222
            }"#,
            "prt",
        );
        assert_unknown::<SshTunnelConfig>(
            r#"{
                "gateway_host": "gateway.example.test",
                "gateway_user": "operator",
                "remote_port": 41000,
                "gatway_host": "typo"
            }"#,
            "gatway_host",
        );
        assert_unknown::<SshTlsProxyConfig>(
            r#"{
                "program": "proxy",
                "server_name": "gateway.example.test",
                "server_nam": "typo"
            }"#,
            "server_nam",
        );
    }

    #[test]
    fn older_agent_config_still_uses_supported_defaults() {
        let config: AgentConfig = serde_json::from_str(
            r#"{
                "version": 1,
                "name": "agent"
            }"#,
        )
        .expect("supported older config");
        assert_eq!(config.listen, SocketAddr::from(([127, 0, 0, 1], 27391)));
        assert_eq!(config.secret_env, "ONEC_AGENT_SECRET");
        assert!(config.ssh.is_none());
        assert!(config.ssh_server.is_none());
        assert!(config.embedded_ssh_server.is_none());
    }

    #[test]
    fn agent_json_rejects_static_ssh_policy_before_runtime() {
        let error = serde_json::from_str::<AgentConfig>(
            r#"{"version":1,"name":"agent","listen":"127.0.0.1:0"}"#,
        )
        .expect_err("zero control port must fail at JSON ingress");
        assert!(
            error.to_string().contains("control port must be non-zero"),
            "{error}"
        );

        for (ssh, expected) in [
            (
                serde_json::json!({"gateway_host":"edge.example.test","gateway_user":"agent","remote_port":0,"identity":"id","known_hosts":"known_hosts"}),
                "non-zero",
            ),
            (
                serde_json::json!({"gateways":[{"host":"edge.example.test","user":"agent","port":22},{"host":"EDGE.example.test","user":"agent","port":22}],"remote_port":41000,"identity":"id","known_hosts":"known_hosts"}),
                "unique",
            ),
            (
                serde_json::json!({"gateway_host":"edge.example.test","gateway_user":"agent","remote_port":41000,"identity":"id","known_hosts":"known_hosts","tls_proxy":{"program":"openssl","server_name":"unsafe name"}}),
                "unsafe characters",
            ),
        ] {
            let error = serde_json::from_value::<AgentConfig>(serde_json::json!({
                "version": 1,
                "name": "agent",
                "ssh": ssh
            }))
            .expect_err("unsafe static SSH config must fail at JSON ingress");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn legacy_tunnel_config_migrates_to_one_canonical_gateway() {
        let config: SshTunnelConfig = serde_json::from_value(serde_json::json!({
            "gateway_host": "gateway.example.test",
            "gateway_user": "agent",
            "gateway_port": 2222,
            "remote_port": 41001,
            "identity": "id_ed25519",
            "known_hosts": "known_hosts",
            "tls_proxy": {
                "program": "openssl.exe",
                "server_name": "edge.example.test",
                "alpn": "http/1.1"
            }
        }))
        .expect("legacy config migrates");
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].host, "gateway.example.test");
        assert_eq!(config.gateways[0].user, "agent");
        assert_eq!(config.gateways[0].port, 2222);
        assert!(config.gateways[0].tls_proxy.is_some());
        let serialized = serde_json::to_value(&config).expect("canonical config");
        let ssh = serialized.as_object().expect("tunnel object");
        assert!(ssh.contains_key("gateways"));
        assert!(!ssh.contains_key("gateway_host"));
        assert!(!ssh.contains_key("gateway_user"));
        assert!(!ssh.contains_key("gateway_port"));
        assert!(!ssh.contains_key("tls_proxy"));
    }

    #[test]
    fn tunnel_config_rejects_mixed_gateway_schemas() {
        let error = serde_json::from_value::<SshTunnelConfig>(serde_json::json!({
            "gateways": [{"host": "new.example.test", "user": "agent", "port": 22}],
            "gateway_host": "old.example.test",
            "gateway_user": "agent",
            "remote_port": 41001
        }))
        .expect_err("mixed schemas must fail");
        assert!(error.to_string().contains("either gateways[] or legacy"));
    }
}
