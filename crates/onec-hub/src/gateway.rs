//! Shared managed gateway topology values.

use serde::{Deserialize, Serialize};

fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One approved SSH edge used by managed agents and controllers.
pub struct GatewayEndpoint {
    /// Gateway hostname or IP address.
    pub host: String,
    /// Restricted SSH account used by managed reverse tunnels/controllers.
    pub user: String,
    /// SSH listen port.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Full pinned OpenSSH host public key line.
    pub host_public_key: String,
}

impl GatewayEndpoint {
    /// Creates one endpoint with the default SSH port.
    pub fn new(
        host: impl Into<String>,
        user: impl Into<String>,
        host_public_key: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            user: user.into(),
            port: default_ssh_port(),
            host_public_key: host_public_key.into(),
        }
    }

    /// Validates transport fields that do not require SSH-key parsing.
    pub fn validate_fields(&self) -> Result<(), &'static str> {
        if self.host.trim().is_empty() {
            return Err("gateway host must not be empty");
        }
        if self.user.trim().is_empty() {
            return Err("gateway user must not be empty");
        }
        if self.port == 0 {
            return Err("gateway SSH port must be non-zero");
        }
        if self.host_public_key.trim().is_empty() {
            return Err("gateway host public key must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_defaults_to_standard_ssh_port() {
        let endpoint: GatewayEndpoint = serde_json::from_value(serde_json::json!({
            "host": "gateway.example.test",
            "user": "agent",
            "host_public_key": "ssh-ed25519 AAAATEST"
        }))
        .expect("endpoint");
        assert_eq!(endpoint.port, 22);
        assert!(endpoint.validate_fields().is_ok());
    }
}
