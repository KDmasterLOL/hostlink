//! Agent configuration, secret resolution, and SSH boundary validation.
//!
//! This subsystem owns the persisted JSON schema and validates loopback control, user-mode sshd,
//! and managed reverse-SSH tunnel invariants before any process is spawned.

use super::*;

mod agent;
mod model;
mod sshd;
mod tunnel;

pub use model::{
    AgentConfig, EmbeddedSshServerConfig, SshGatewayEndpoint, SshServerConfig, SshTlsProxyConfig,
    SshTunnelConfig,
};
#[cfg(test)]
pub(super) use sshd::validate_user_sshd_config;
