//! Embedded SSH Agent: authenticated transport, execution, and durable jobs.
//! The former Agent JSONL listener, OpenSSH process and updater are absent.

pub mod enrollment;
pub mod exec;
pub mod jobs;
pub mod service;
pub mod sftp;
pub mod ssh;
pub mod tunnel;
pub mod update;
pub mod update_handoff;

use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for a loopback-bound SSH Agent running as an unprivileged user.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub listen: SocketAddr,
    pub user: String,
    pub host_key: PathBuf,
    pub authorized_keys: PathBuf,
    pub jobs_root: PathBuf,
    pub gateway: Option<ReverseGateway>,
    /// Hub-approved fallback routes, ordered after the explicitly selected primary.
    #[serde(default)]
    pub gateway_alternates: Vec<ReverseGateway>,
}

/// Optional pinned reverse-SSH gateway.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseGateway {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity: PathBuf,
    pub host_public_key: PathBuf,
    pub remote_port: u16,
}
impl AgentConfig {
    /// Validate network exposure and credentials before performing any effects.
    pub fn validate(&self) -> io::Result<()> {
        if !self.listen.ip().is_loopback() || self.listen.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH listener must be loopback and nonzero",
            ));
        }
        if self.user.trim().is_empty()
            || self.host_key.as_os_str().is_empty()
            || self.authorized_keys.as_os_str().is_empty()
            || self.jobs_root.as_os_str().is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Agent user, host key, authorized keys and jobs root are required",
            ));
        }
        if self.gateway.is_none() && !self.gateway_alternates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "approved gateway alternates require an explicit primary gateway",
            ));
        }
        let routes: Vec<_> = self
            .gateway
            .iter()
            .chain(self.gateway_alternates.iter())
            .collect();
        if routes.len() > 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at most 16 approved gateway routes are allowed",
            ));
        }
        let mut route_ids = std::collections::BTreeSet::new();
        let mut pin_paths = std::collections::BTreeSet::new();
        let mut remote_port = None;
        for g in routes {
            if g.host.trim().is_empty()
                || g.user.trim().is_empty()
                || g.port == 0
                || g.remote_port == 0
                || g.identity.as_os_str().is_empty()
                || g.host_public_key.as_os_str().is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Gateway needs exact endpoint, credentials and reverse port",
                ));
            }
            if remote_port
                .replace(g.remote_port)
                .is_some_and(|port| port != g.remote_port)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "approved gateway routes must use the same assigned reverse port",
                ));
            }
            if !route_ids.insert((g.host.to_ascii_lowercase(), g.port, g.user.clone())) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate approved gateway identity",
                ));
            }
            if !pin_paths.insert(g.host_public_key.clone()) || g.identity == g.host_public_key {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "approved gateway routes have conflicting key file paths",
                ));
            }
            if self
                .gateway
                .as_ref()
                .is_some_and(|primary| primary.identity != g.identity)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "approved gateway routes must use the same Agent identity file",
                ));
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_rejects_public_listener() {
        let cfg = AgentConfig {
            listen: "0.0.0.0:12345".parse().unwrap(),
            user: "test".into(),
            host_key: "key".into(),
            authorized_keys: "keys".into(),
            jobs_root: "jobs".into(),
            gateway: None,
            gateway_alternates: Vec::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn old_single_gateway_json_deserializes_without_alternates() {
        let config: AgentConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:2200","user":"agent","host_key":"host","authorized_keys":"authorized","jobs_root":"jobs","gateway":null}"#,
        )
        .expect("legacy single-gateway configuration");
        assert!(config.gateway.is_none());
        assert!(config.gateway_alternates.is_empty());
    }
}
