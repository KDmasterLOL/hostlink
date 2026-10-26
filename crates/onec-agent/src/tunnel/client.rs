//! In-process russh reverse-tunnel client and lifecycle ownership.

use super::*;
use crate::config::SshGatewayEndpoint;
use crate::environment::AgentEnvironmentPolicy;
use processkit::RunningProcess;
use russh::Disconnect;
use russh::client;
use russh::keys::{Algorithm, PrivateKeyWithHashAlg};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const SSH_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct TunnelFailure {
    category: &'static str,
    retryable: bool,
    detail: String,
}

impl std::fmt::Display for TunnelFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.category, self.detail)
    }
}

impl std::error::Error for TunnelFailure {}

pub(super) struct TunnelFailureClass {
    pub(super) category: &'static str,
    pub(super) retryable: bool,
}

pub(super) fn classify_tunnel_failure(error: &io::Error) -> TunnelFailureClass {
    if let Some(failure) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<TunnelFailure>())
    {
        TunnelFailureClass {
            category: failure.category,
            retryable: failure.retryable,
        }
    } else {
        TunnelFailureClass {
            category: match error.kind() {
                io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => "invalid_config",
                io::ErrorKind::PermissionDenied => "authorization_denied",
                _ => "transport",
            },
            retryable: !matches!(
                error.kind(),
                io::ErrorKind::InvalidData
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::PermissionDenied
            ),
        }
    }
}

fn permanent_failure(category: &'static str, detail: impl Into<String>) -> io::Error {
    // Keep the old public I/O error categories stable. In particular,
    // callers already use PermissionDenied to recognize rejected SSH keys.
    let kind = match category {
        "authentication_denied" | "host_key_mismatch" | "forward_denied" => {
            io::ErrorKind::PermissionDenied
        }
        "invalid_identity" | "invalid_config" => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        TunnelFailure {
            category,
            retryable: false,
            detail: detail.into(),
        },
    )
}

pub(super) struct ReverseTunnel {
    session: client::Handle<super::forward::GatewayHandler>,
    remote_port: u16,
    connected_at: tokio::time::Instant,
    session_uptime: Option<Duration>,
    proxy: Option<RunningProcess>,
    bridge_shutdown: Option<oneshot::Sender<()>>,
    bridge_task: Option<JoinHandle<()>>,
}

impl ReverseTunnel {
    pub(super) async fn connect(
        config: &SshTunnelConfig,
        gateway: &SshGatewayEndpoint,
        local_target_port: u16,
        environment: &AgentEnvironmentPolicy,
    ) -> io::Result<Self> {
        let deadline = tokio::time::Instant::now() + SSH_ESTABLISH_TIMEOUT;
        Self::connect_inner(config, gateway, local_target_port, environment, deadline).await
    }

    async fn connect_inner(
        config: &SshTunnelConfig,
        gateway: &SshGatewayEndpoint,
        local_target_port: u16,
        environment: &AgentEnvironmentPolicy,
        deadline: tokio::time::Instant,
    ) -> io::Result<Self> {
        let identity = config.identity_path()?;
        let known_hosts = config.known_hosts_path()?;
        let private_key = russh::keys::load_secret_key(identity, None).map_err(|error| {
            permanent_failure(
                "invalid_identity",
                format!(
                    "failed to load managed SSH identity {}: {error}",
                    identity.display()
                ),
            )
        })?;
        if private_key.algorithm() != Algorithm::Ed25519 {
            return Err(permanent_failure(
                "invalid_identity",
                format!(
                    "managed SSH identity {} must be an Ed25519 OpenSSH private key",
                    identity.display()
                ),
            ));
        }

        let (forward_tx, forward_rx) = mpsc::channel(super::forward::MAX_FORWARD_CHANNELS);
        let handler = super::forward::GatewayHandler {
            host: gateway.host.clone(),
            port: gateway.port,
            known_hosts: known_hosts.to_owned(),
            remote_port: config.remote_port,
            forwards: forward_tx,
        };
        let super::proxy::GatewayConnection { stream, mut proxy } =
            super::proxy::connect_gateway_stream(gateway, environment).await?;
        let ssh_config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });
        let mut session = match tokio::time::timeout_at(
            deadline,
            client::connect_stream(ssh_config, stream, handler),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(ssh_error("establishing SSH transport", error));
            }
            Err(_) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timed out establishing managed reverse SSH to {}:{} after {} seconds",
                        gateway.host,
                        gateway.port,
                        SSH_ESTABLISH_TIMEOUT.as_secs()
                    ),
                ));
            }
        };

        let authentication = match tokio::time::timeout_at(
            deadline,
            session.authenticate_publickey(
                gateway.user.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(private_key), None),
            ),
        )
        .await
        {
            Ok(Ok(authentication)) => authentication,
            Ok(Err(error)) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(ssh_error("authenticating managed SSH identity", error));
            }
            Err(_) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed reverse SSH authentication timed out",
                ));
            }
        };
        if !authentication.success() {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                session.disconnect(Disconnect::ByApplication, "authentication rejected", "en"),
            )
            .await;
            let _ = super::proxy::stop_proxy_process(&mut proxy).await;
            return Err(permanent_failure(
                "authentication_denied",
                format!(
                    "gateway {}:{} rejected managed SSH identity for user {}",
                    gateway.host, gateway.port, gateway.user
                ),
            ));
        }

        match tokio::time::timeout_at(
            deadline,
            session.tcpip_forward("127.0.0.1", u32::from(config.remote_port)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(ssh_error("requesting reverse loopback forwarding", error));
            }
            Err(_) => {
                let _ = super::proxy::stop_proxy_process(&mut proxy).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed reverse SSH forward request timed out",
                ));
            }
        }
        let connected_at = tokio::time::Instant::now();

        let (bridge_shutdown, bridge_shutdown_rx) = oneshot::channel();
        let bridge_task = tokio::spawn(super::forward::run_bridge_manager(
            forward_rx,
            local_target_port,
            bridge_shutdown_rx,
        ));

        Ok(Self {
            session,
            remote_port: config.remote_port,
            connected_at,
            session_uptime: None,
            proxy,
            bridge_shutdown: Some(bridge_shutdown),
            bridge_task: Some(bridge_task),
        })
    }

    pub(super) async fn wait(&mut self) -> io::Result<()> {
        let result = (&mut self.session)
            .await
            .map_err(|error| ssh_error("waiting for SSH session", error));
        self.session_uptime = Some(self.connected_at.elapsed());
        self.stop_bridges().await;
        let proxy_result = super::proxy::stop_proxy_process(&mut self.proxy).await;
        result.and(proxy_result)
    }

    pub(super) fn session_uptime(&self) -> Duration {
        self.session_uptime
            .unwrap_or_else(|| self.connected_at.elapsed())
    }

    pub(super) async fn shutdown(&mut self) -> io::Result<()> {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.session
                .cancel_tcpip_forward("127.0.0.1", u32::from(self.remote_port)),
        )
        .await;
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.session
                .disconnect(Disconnect::ByApplication, "onec-agent shutdown", "en"),
        )
        .await;

        let session_result = tokio::time::timeout(super::SHUTDOWN_GRACE, &mut self.session).await;
        self.stop_bridges().await;
        let session_result = match session_result {
            Ok(Ok(())) | Ok(Err(russh::Error::Disconnect)) => Ok(()),
            Ok(Err(error)) => Err(ssh_error("closing SSH session", error)),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH session shutdown timed out",
            )),
        };
        let proxy_result = super::proxy::stop_proxy_process(&mut self.proxy).await;
        session_result.and(proxy_result)
    }

    async fn stop_bridges(&mut self) {
        if let Some(shutdown) = self.bridge_shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(mut task) = self.bridge_task.take() else {
            return;
        };
        if tokio::time::timeout(super::SHUTDOWN_GRACE, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

fn ssh_error(context: &str, error: russh::Error) -> io::Error {
    let (category, retryable) = match &error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => ("host_key_mismatch", false),
        russh::Error::NotAuthenticated | russh::Error::NoAuthMethod => {
            ("authentication_denied", false)
        }
        russh::Error::RequestDenied => ("forward_denied", false),
        russh::Error::InvalidConfig(_)
        | russh::Error::Keys(_)
        | russh::Error::SshKey(_)
        | russh::Error::CouldNotReadKey
        | russh::Error::NoCommonAlgo { .. }
        | russh::Error::WrongServerSig
        | russh::Error::Version => ("invalid_config", false),
        russh::Error::IO(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::PermissionDenied
            ) =>
        {
            ("invalid_config", false)
        }
        russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::HUP
        | russh::Error::Disconnect
        | russh::Error::IO(_) => ("transport", true),
        _ => ("ssh_protocol", true),
    };
    let kind = match &error {
        russh::Error::IO(io_error) => io_error.kind(),
        _ if !retryable => match category {
            "invalid_config" => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::PermissionDenied,
        },
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        TunnelFailure {
            category,
            retryable,
            detail: format!("{context}: {error}"),
        },
    )
}

#[cfg(test)]
#[path = "tests.rs"]
pub(super) mod tests;

#[cfg(test)]
mod failure_tests {
    use super::*;

    #[test]
    fn ssh_failure_classification_is_typed_and_fails_closed_for_identity_policy() {
        for (error, category) in [
            (russh::Error::UnknownKey, "host_key_mismatch"),
            (russh::Error::KeyChanged { line: 3 }, "host_key_mismatch"),
            (russh::Error::NotAuthenticated, "authentication_denied"),
            (russh::Error::RequestDenied, "forward_denied"),
        ] {
            let classified = classify_tunnel_failure(&ssh_error("fixture", error));
            assert_eq!(classified.category, category);
            assert!(!classified.retryable);
        }

        let transient = classify_tunnel_failure(&ssh_error(
            "fixture",
            russh::Error::IO(io::Error::from(io::ErrorKind::ConnectionReset)),
        ));
        assert_eq!(transient.category, "transport");
        assert!(transient.retryable);

        let auth_rejected = permanent_failure("authentication_denied", "fixture");
        let classified = classify_tunnel_failure(&auth_rejected);
        assert_eq!(classified.category, "authentication_denied");
        assert!(!classified.retryable);
        assert_eq!(auth_rejected.kind(), io::ErrorKind::PermissionDenied);
        let invalid_key = permanent_failure("invalid_identity", "fixture");
        assert_eq!(invalid_key.kind(), io::ErrorKind::InvalidData);
        assert!(!classify_tunnel_failure(&invalid_key).retryable);
        let no_credentials = ssh_error(
            "fixture",
            russh::Error::IO(io::Error::from(io::ErrorKind::PermissionDenied)),
        );
        assert_eq!(no_credentials.kind(), io::ErrorKind::PermissionDenied);
        assert!(!classify_tunnel_failure(&no_credentials).retryable);
    }
}
