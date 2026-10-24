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

pub(super) struct ReverseTunnel {
    session: client::Handle<super::forward::GatewayHandler>,
    remote_port: u16,
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
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to load managed SSH identity {}: {error}",
                    identity.display()
                ),
            )
        })?;
        if private_key.algorithm() != Algorithm::Ed25519 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
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
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
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

        let (bridge_shutdown, bridge_shutdown_rx) = oneshot::channel();
        let bridge_task = tokio::spawn(super::forward::run_bridge_manager(
            forward_rx,
            local_target_port,
            bridge_shutdown_rx,
        ));

        Ok(Self {
            session,
            remote_port: config.remote_port,
            proxy,
            bridge_shutdown: Some(bridge_shutdown),
            bridge_task: Some(bridge_task),
        })
    }

    pub(super) async fn wait(&mut self) -> io::Result<()> {
        let result = (&mut self.session)
            .await
            .map_err(|error| ssh_error("waiting for SSH session", error));
        self.stop_bridges().await;
        let proxy_result = super::proxy::stop_proxy_process(&mut self.proxy).await;
        result.and(proxy_result)
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
    io::Error::other(format!("{context}: {error}"))
}

#[cfg(test)]
#[path = "tests.rs"]
pub(super) mod tests;
