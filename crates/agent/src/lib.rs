//! Embedded SSH Agent: authenticated transport, execution, and durable jobs.
//! The former Agent JSONL listener, OpenSSH process and updater are absent.

pub mod exec;
pub mod jobs;
pub mod sftp;
pub mod ssh;
pub mod tunnel;
pub mod update;

use serde::Deserialize;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for a loopback-bound SSH Agent running as an unprivileged user.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub listen: SocketAddr,
    pub user: String,
    pub host_key: PathBuf,
    pub authorized_keys: PathBuf,
    pub jobs_root: PathBuf,
    pub gateway: Option<ReverseGateway>,
}

/// Optional pinned reverse-SSH gateway.
#[derive(Clone, Debug, Deserialize)]
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
        if let Some(g) = &self.gateway
            && (g.host.trim().is_empty()
                || g.user.trim().is_empty()
                || g.port == 0
                || g.remote_port == 0
                || g.identity.as_os_str().is_empty()
                || g.host_public_key.as_os_str().is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Gateway needs exact endpoint, credentials and reverse port",
            ));
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
        };
        assert!(cfg.validate().is_err());
    }
}
