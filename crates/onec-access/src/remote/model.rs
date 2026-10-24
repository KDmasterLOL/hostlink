//! Public remote server/client value types.

use super::ssh::RemoteChannel;
use crate::AppResult;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use std::path::PathBuf;
use std::{
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Transport carrier used to reach a resident target agent.
pub enum RemoteCarrier {
    /// The gateway reverse listener points directly at the loopback onec-agent control endpoint.
    /// This is the supported compatibility carrier for managed hosts without target-side sshd.
    #[default]
    GatewayControl,
    /// The gateway reverse listener points at target-side sshd; agent control is reached with SSH -W.
    TargetSsh,
}

#[derive(Debug, Clone)]
/// Strict host-key source for one approved gateway route.
pub enum GatewayTrust {
    /// Exact OpenSSH public-key pin supplied by the authenticated hub.
    PinnedPublicKey(String),
    /// Legacy local fallback verified against the configured known_hosts file.
    KnownHosts(PathBuf),
}

#[derive(Debug, Clone)]
/// One ordered SSH gateway route and its explicit trust source.
pub struct GatewayRoute {
    /// Gateway hostname/address.
    pub host: String,
    /// SSH gateway user.
    pub user: String,
    /// SSH gateway port.
    pub port: u16,
    /// Strict host-key trust policy.
    pub trust: GatewayTrust,
}

impl GatewayRoute {
    pub(crate) fn validate(&self) -> AppResult<()> {
        if self.host.trim().is_empty() || self.user.trim().is_empty() || self.port == 0 {
            return Err(crate::invalid_config(
                "gateway route requires non-empty host/user and non-zero port".to_owned(),
            ));
        }
        if let GatewayTrust::PinnedPublicKey(value) = &self.trust {
            use russh::keys::ssh_key::{Algorithm, PublicKey};
            let key = PublicKey::from_openssh(value).map_err(|_| {
                crate::invalid_config(format!(
                    "hub gateway {}:{} has an invalid host public key",
                    self.host, self.port
                ))
            })?;
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(crate::invalid_config(format!(
                    "hub gateway {}:{} host public key must use Ed25519",
                    self.host, self.port
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
/// Fully projected connection/trust/runtime parameters for one remote managed host.
pub struct RemoteServer {
    /// Human-readable managed host name.
    pub name: String,
    /// Ordered approved gateway routes used for transport establishment.
    pub gateways: Vec<GatewayRoute>,
    /// Reverse-listener port assigned to this target on gateway loopback.
    pub remote_port: u16,
    /// Carrier used to reach agent control.
    pub carrier: RemoteCarrier,
    /// Enrollment persistence metadata from onec-hub. Older/static records may not provide it.
    pub persistence_mode: Option<String>,
    /// Optional controller SSH private-key path.
    pub identity: Option<PathBuf>,
    /// Optional local known_hosts path used by generated OpenSSH convenience config.
    pub known_hosts: Option<PathBuf>,
    /// Target SSH user when using [`RemoteCarrier::TargetSsh`].
    pub target_user: Option<String>,
    /// Pinned target known_hosts file for embedded target SSH.
    pub target_known_hosts: Option<PathBuf>,
    /// Stable target host-key alias used for known_hosts verification.
    pub target_host_key_alias: Option<String>,
    /// Ephemeral control secret supplied by onec-hub. Never serialize or persist this runtime value.
    pub(crate) secret: SecretString,
}

impl RemoteServer {
    /// Validates required identity, secret, port, and target-SSH trust fields.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when mandatory connection/trust state is missing or invalid.
    pub fn validate(&self) -> AppResult<()> {
        if self.name.trim().is_empty()
            || self.gateways.is_empty()
            || self.secret.expose_secret().trim().is_empty()
        {
            return Err(crate::invalid_config(
                "remote server name, gateway host/user and agent control secret are required"
                    .to_owned(),
            ));
        }
        if self.secret.expose_secret().trim().len() < 16 {
            return Err(crate::invalid_config(
                "remote agent control secret must contain at least 16 characters".to_owned(),
            ));
        }
        if self.remote_port == 0 {
            return Err(crate::invalid_config(
                "remote SSH ports must be non-zero".to_owned(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for gateway in &self.gateways {
            gateway.validate()?;
            if !seen.insert((gateway.host.to_ascii_lowercase(), gateway.port)) {
                return Err(crate::invalid_config(
                    "remote gateway routes contain duplicate host/port endpoints".to_owned(),
                ));
            }
        }
        if self.carrier == RemoteCarrier::TargetSsh
            && (self
                .target_user
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
                || self.target_known_hosts.is_none()
                || self
                    .target_host_key_alias
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty()))
        {
            return Err(crate::invalid_config(
                "hub-managed target SSH transport requires target user, target known_hosts and host-key alias"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn secret(&self) -> AppResult<&str> {
        let secret = self.secret.expose_secret();
        if secret.trim().len() < 16 {
            return Err(crate::invalid_config(
                "remote agent control secret must contain at least 16 characters".to_owned(),
            ));
        }
        Ok(secret)
    }
}

#[derive(Debug, Clone)]
/// Cloneable controller client for one projected remote agent.
pub struct RemoteAgentClient {
    pub(super) server: RemoteServer,
    pub(super) capabilities: Arc<OnceLock<Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Agent-owned paths used by one content-addressed local-executable run.
pub struct RemoteRunLocalPaths {
    /// Persistent immutable content cache root.
    pub cache_root: String,
    /// Parent root that bounds identity-owned run cleanup.
    pub run_root_parent: String,
    /// Unique working directory owned by this run identity.
    pub run_root: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// Result of a carrier-aware remote TCP reachability probe.
pub struct RemoteProbeResult {
    /// Whether the remote TCP target was reached.
    pub reachable: bool,
    /// Human-readable transport failure when the probe was not reachable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Bidirectional byte stream bridged through the selected remote carrier.
pub struct RemoteTcpStream {
    pub(super) channel: RemoteChannel,
}

impl RemoteTcpStream {
    /// Closes the stream and reports transport shutdown or disconnect failures.
    pub async fn finish(&mut self) -> AppResult<()> {
        self.channel.finish().await
    }
}

impl AsyncRead for RemoteTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_read(cx, buf)
    }
}

impl AsyncWrite for RemoteTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.channel).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_shutdown(cx)
    }
}
