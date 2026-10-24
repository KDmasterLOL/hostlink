//! Approved-route SSH connection establishment and session cleanup.

use super::channel::EmbeddedSshChannel;
use super::phase::{ApprovedRoutesFailure, connection_phase};
use super::trust::{StrictKnownHost, StrictTrust, authenticate, required_file, required_text};
use super::{
    GATEWAY_ADMISSION_TIMEOUT, MANAGED_AGENT_CONTROL_PORT, SSH_CONNECT_TIMEOUT,
    SSH_SESSION_CLEANUP_TIMEOUT,
};
use crate::remote::SFTP_IO_STAGE_DEADLINE;
use crate::remote::model::{GatewayRoute, GatewayTrust, RemoteCarrier, RemoteServer};
use crate::{AppResult, invalid_config};
use anyhow::{Context, bail};
use russh::ChannelMsg;
use russh::client;
use russh::keys::Algorithm;
use russh::keys::ssh_key::PublicKey;
use russh_sftp::client::SftpSession;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

async fn open_direct_tcpip(
    session: &client::Handle<StrictKnownHost>,
    host: &str,
    port: u32,
    phase: &'static str,
    limit: Duration,
) -> anyhow::Result<russh::Channel<client::Msg>> {
    connection_phase(phase, tokio::time::Instant::now() + limit, async {
        session
            .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
            .await
            .map_err(anyhow::Error::from)
    })
    .await
}

#[derive(Debug, thiserror::Error)]
#[error("connection cleanup could not be confirmed")]
pub(super) struct ConnectionCleanupUnconfirmed(#[source] pub(super) Option<anyhow::Error>);

pub(super) async fn close_session(
    session: &mut client::Handle<StrictKnownHost>,
    description: &str,
    deadline: Option<tokio::time::Instant>,
) -> anyhow::Result<()> {
    // A peer may already have closed the connection when we request disconnect.
    // Only a pending join leaves ownership unconfirmed; terminal protocol errors
    // do not imply that cleanup is still running.
    match deadline {
        Some(deadline) => {
            let _ = tokio::time::timeout_at(
                deadline,
                session.disconnect(russh::Disconnect::ByApplication, description, "en"),
            )
            .await;
            if tokio::time::timeout_at(deadline, session).await.is_err() {
                return Err(ConnectionCleanupUnconfirmed(None).into());
            }
        }
        None => {
            let _ = tokio::time::timeout(
                SSH_SESSION_CLEANUP_TIMEOUT,
                session.disconnect(russh::Disconnect::ByApplication, description, "en"),
            )
            .await;
            if tokio::time::timeout(SSH_SESSION_CLEANUP_TIMEOUT, session)
                .await
                .is_err()
            {
                return Err(ConnectionCleanupUnconfirmed(None).into());
            }
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("target SSH server rejected the SFTP subsystem")]
pub(super) struct SftpSubsystemUnsupported;
#[derive(Clone)]
pub(super) enum FinalTarget {
    AgentControl,
    TargetTcp {
        host: String,
        port: u16,
        timeout: Duration,
    },
    TargetSftp,
}

pub(super) enum FinalIo {
    Stream(russh::ChannelStream<client::Msg>),
    Sftp(SftpSession),
}
impl EmbeddedSshChannel {
    pub(in crate::remote) async fn select_gateway_route(
        gateways: &[GatewayRoute],
        identity: &Path,
        reverse_port: u16,
    ) -> AppResult<usize> {
        if gateways.is_empty() || reverse_port == 0 {
            return Err(invalid_config(
                "managed SSH admission requires approved gateways and a non-zero reverse port"
                    .to_owned(),
            ));
        }
        let identity = required_file(Some(identity), "managed SSH identity")?;
        let private_key = russh::keys::load_secret_key(&identity, None)
            .with_context(|| format!("loading managed SSH identity {}", identity.display()))?;
        if private_key.algorithm() != Algorithm::Ed25519 {
            bail!(
                "managed SSH identity {} must be an Ed25519 OpenSSH private key",
                identity.display()
            );
        }
        let private_key = Arc::new(private_key);

        let mut failures = Vec::new();
        for (index, route) in gateways.iter().enumerate() {
            route.validate()?;
            let deadline = tokio::time::Instant::now() + GATEWAY_ADMISSION_TIMEOUT;
            let config = Self::gateway_config();
            let mut session =
                match Self::connect_gateway(route, private_key.clone(), config, Some(deadline))
                    .await
                {
                    Ok(session) => session,
                    Err(error)
                        if error
                            .downcast_ref::<ConnectionCleanupUnconfirmed>()
                            .is_some() =>
                    {
                        return Err(error);
                    }
                    Err(error) => {
                        failures.push(format!("gateway[{index}] {error}"));
                        continue;
                    }
                };
            let admission = connection_phase("gateway_direct_tcpip", deadline, async {
                let channel = session
                    .channel_open_direct_tcpip("127.0.0.1", reverse_port.into(), "127.0.0.1", 0)
                    .await?;
                let mut stream = channel.into_stream();
                stream.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            })
            .await;
            match admission {
                Ok(()) => {
                    close_session(
                        &mut session,
                        "gateway admission probe complete",
                        Some(deadline),
                    )
                    .await?;
                    return Ok(index);
                }
                Err(error) => {
                    failures.push(format!("gateway[{index}] {error}"));
                    close_session(
                        &mut session,
                        "gateway admission probe failed",
                        Some(deadline),
                    )
                    .await?;
                }
            }
        }

        Err(invalid_config(format!(
            "all approved gateway routes failed managed SSH admission: {}",
            failures.join("; ")
        )))
    }

    pub(super) async fn connect_control(server: &RemoteServer) -> AppResult<Self> {
        Self::connect(server, FinalTarget::AgentControl).await
    }

    pub(super) async fn connect_target_tcp(
        server: &RemoteServer,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> AppResult<Self> {
        if server.carrier != RemoteCarrier::TargetSsh {
            return Err(invalid_config(
                "native target SSH TCP channels require the TargetSsh carrier".to_owned(),
            ));
        }
        Self::connect(
            server,
            FinalTarget::TargetTcp {
                host: host.to_owned(),
                port,
                timeout,
            },
        )
        .await
    }

    pub(super) async fn connect_sftp(server: &RemoteServer) -> AppResult<Option<Self>> {
        if server.carrier != RemoteCarrier::TargetSsh {
            return Err(invalid_config(
                "SFTP requires the TargetSsh carrier".to_owned(),
            ));
        }
        match Self::connect(server, FinalTarget::TargetSftp).await {
            Ok(channel) => Ok(Some(channel)),
            Err(error) if error.downcast_ref::<SftpSubsystemUnsupported>().is_some() => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn connect(server: &RemoteServer, final_target: FinalTarget) -> AppResult<Self> {
        let identity = required_file(server.identity.as_deref(), "managed SSH identity")?;
        let private_key = russh::keys::load_secret_key(&identity, None)
            .with_context(|| format!("loading managed SSH identity {}", identity.display()))?;
        if private_key.algorithm() != Algorithm::Ed25519 {
            bail!(
                "managed SSH identity {} must be an Ed25519 OpenSSH private key",
                identity.display()
            );
        }
        let private_key = Arc::new(private_key);
        let target_known_hosts = if server.carrier == RemoteCarrier::TargetSsh {
            Some(required_file(
                server.target_known_hosts.as_deref(),
                "target known_hosts",
            )?)
        } else {
            None
        };
        let mut failures = Vec::new();
        for (index, route) in server.gateways.iter().enumerate() {
            match Self::connect_endpoint(
                server,
                final_target.clone(),
                route,
                private_key.clone(),
                target_known_hosts.clone(),
            )
            .await
            {
                Ok(channel) => return Ok(channel),
                Err(error)
                    if error
                        .downcast_ref::<ConnectionCleanupUnconfirmed>()
                        .is_some() =>
                {
                    return Err(error);
                }
                Err(error) if error.downcast_ref::<SftpSubsystemUnsupported>().is_some() => {
                    return Err(error);
                }
                Err(error) => failures.push((index, error)),
            }
        }
        Err(ApprovedRoutesFailure::from_route_failures(&failures).into())
    }

    fn gateway_config() -> Arc<client::Config> {
        Arc::new(client::Config {
            inactivity_timeout: Some(SFTP_IO_STAGE_DEADLINE),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        })
    }

    async fn connect_gateway(
        route: &GatewayRoute,
        private_key: Arc<russh::keys::PrivateKey>,
        config: Arc<client::Config>,
        route_deadline: Option<tokio::time::Instant>,
    ) -> AppResult<client::Handle<StrictKnownHost>> {
        let trust = match &route.trust {
            GatewayTrust::KnownHosts(path) => {
                StrictTrust::KnownHosts(required_file(Some(path), "gateway known_hosts")?)
            }
            GatewayTrust::PinnedPublicKey(value) => {
                let key = PublicKey::from_openssh(value)
                    .context("parsing approved gateway host-key pin")?;
                if key.algorithm() != Algorithm::Ed25519 {
                    bail!("approved gateway host-key pin must be Ed25519");
                }
                StrictTrust::Pinned(key)
            }
        };
        let handler = StrictKnownHost {
            host: route.host.clone(),
            port: route.port,
            trust,
        };
        let connect = async {
            client::connect(config, (route.host.as_str(), route.port), handler)
                .await
                .context("connecting with strict gateway host-key checking")
        };
        let connect_deadline =
            route_deadline.unwrap_or_else(|| tokio::time::Instant::now() + SSH_CONNECT_TIMEOUT);
        let mut session = connection_phase("gateway_connect", connect_deadline, connect).await?;
        let authenticate = async {
            authenticate(&mut session, &route.user, private_key, "gateway".to_owned()).await
        };
        let auth_deadline =
            route_deadline.unwrap_or_else(|| tokio::time::Instant::now() + SSH_CONNECT_TIMEOUT);
        if let Err(error) = connection_phase("gateway_connect", auth_deadline, authenticate).await {
            match route_deadline {
                Some(deadline) => {
                    close_session(
                        &mut session,
                        "gateway authentication failed",
                        Some(deadline),
                    )
                    .await?;
                }
                None => close_session(&mut session, "gateway authentication failed", None).await?,
            }
            return Err(error);
        }
        Ok(session)
    }

    async fn connect_endpoint(
        server: &RemoteServer,
        final_target: FinalTarget,
        route: &GatewayRoute,
        private_key: Arc<russh::keys::PrivateKey>,
        target_known_hosts: Option<PathBuf>,
    ) -> AppResult<Self> {
        let config = Self::gateway_config();
        let gateway_session =
            Self::connect_gateway(route, private_key.clone(), config.clone(), None).await?;
        let mut gateway_session = gateway_session;
        let mut target_session = None;

        let establishment = async {
            if server.carrier == RemoteCarrier::GatewayControl {
                let FinalTarget::AgentControl = final_target else {
                    bail!("gateway-control transport cannot open a native target SSH TCP channel");
                };
                let channel = open_direct_tcpip(
                    &gateway_session,
                    "127.0.0.1",
                    server.remote_port.into(),
                    "gateway_direct_tcpip",
                    SSH_CONNECT_TIMEOUT,
                )
                .await?;
                return Ok::<_, anyhow::Error>((None, FinalIo::Stream(channel.into_stream())));
            }

            let target_user = required_text(server.target_user.as_deref(), "target SSH user")?;
            let target_host_key_alias = required_text(
                server.target_host_key_alias.as_deref(),
                "target SSH host-key alias",
            )?;
            let target_known_hosts = target_known_hosts
                .as_deref()
                .expect("TargetSsh must have target known_hosts");

            let target_transport = open_direct_tcpip(
                &gateway_session,
                "127.0.0.1",
                server.remote_port.into(),
                "gateway_direct_tcpip",
                SSH_CONNECT_TIMEOUT,
            )
            .await?;

            let target_handler = StrictKnownHost {
                host: target_host_key_alias.to_owned(),
                port: 22,
                trust: StrictTrust::KnownHosts(target_known_hosts.to_path_buf()),
            };
            let target =
                connection_phase(
                    "target_ssh_handshake/auth",
                    tokio::time::Instant::now() + SSH_CONNECT_TIMEOUT,
                    async {
                    client::connect_stream(config, target_transport.into_stream(), target_handler)
                        .await
                })
                .await?;
            target_session = Some(target);
            connection_phase(
                    "target_ssh_handshake/auth",
                    tokio::time::Instant::now() + SSH_CONNECT_TIMEOUT,
                    async {
                authenticate(
                    target_session
                        .as_mut()
                        .expect("target SSH handshake completed"),
                    target_user,
                    private_key,
                    "target SSH server".to_owned(),
                )
                .await
            })
            .await?;

            let final_io = match final_target {
                FinalTarget::AgentControl => FinalIo::Stream(
                    open_direct_tcpip(
                        target_session
                            .as_mut()
                            .expect("target SSH session established"),
                        "127.0.0.1",
                        MANAGED_AGENT_CONTROL_PORT.into(),
                        "agent_control",
                        SSH_CONNECT_TIMEOUT,
                    )
                    .await?
                    .into_stream(),
                ),
                FinalTarget::TargetTcp {
                    host,
                    port,
                    timeout,
                } => FinalIo::Stream(
                    tokio::time::timeout(
                        timeout,
                        target_session
                            .as_mut()
                            .expect("target SSH session established")
                            .channel_open_direct_tcpip(&host, port.into(), "127.0.0.1", 0),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "timed out opening target SSH direct-tcpip channel to {host}:{port} after {} ms",
                            timeout.as_millis()
                        )
                    })?
                    .with_context(|| {
                        format!("opening target SSH direct-tcpip channel to {host}:{port}")
                    })?
                    .into_stream(),
                ),
                FinalTarget::TargetSftp => {
                    // SFTP subsystem confirmation is another SSH channel-open phase. A peer
                    // that never acknowledges it must not hold this managed route indefinitely.
                    // Keep SftpSubsystemUnsupported unwrapped: callers use its typed identity
                    // to distinguish unsupported SFTP from transport failure.
                    tokio::time::timeout(Duration::from_secs(10), async {
                        let mut channel = target_session
                            .as_mut()
                            .expect("target SSH session established")
                            .channel_open_session()
                            .await
                            .context("opening target SSH session channel for SFTP")?;
                        channel
                            .request_subsystem(true, "sftp")
                            .await
                            .context("requesting target SFTP subsystem")?;
                        loop {
                            match channel.wait().await {
                                Some(ChannelMsg::Success) => break,
                                Some(ChannelMsg::Failure) => {
                                    return Err(SftpSubsystemUnsupported.into());
                                }
                                Some(ChannelMsg::WindowAdjusted { .. }) => continue,
                                Some(other) => {
                                    bail!(
                                        "target SSH returned unexpected SFTP subsystem response: {other:?}"
                                    );
                                }
                                None => {
                                    bail!(
                                        "target SSH channel closed before acknowledging the SFTP subsystem"
                                    );
                                }
                            }
                        }
                        Ok::<_, anyhow::Error>(FinalIo::Sftp(
                            SftpSession::new(channel.into_stream())
                                .await
                                .context("initializing target SFTP session")?,
                        ))
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("target_sftp: timed out after 10000 ms"))??
                }
            };

            Ok::<_, anyhow::Error>((target_session.take(), final_io))
        }
        .await;

        let (target_session, final_io) = match establishment {
            Ok(established) => established,
            Err(error) => {
                let target_cleanup = match target_session.take() {
                    Some(mut session) => {
                        close_session(&mut session, "target SSH establishment failed", None)
                            .await
                            .is_ok()
                    }
                    None => true,
                };
                let gateway_cleanup = close_session(
                    &mut gateway_session,
                    "gateway SSH establishment failed",
                    None,
                )
                .await
                .is_ok();
                if !target_cleanup || !gateway_cleanup {
                    return Err(ConnectionCleanupUnconfirmed(None).into());
                }
                return Err(error);
            }
        };

        let (stream, sftp) = match final_io {
            FinalIo::Stream(stream) => (Some(stream), None),
            FinalIo::Sftp(sftp) => (None, Some(sftp)),
        };

        Ok(Self {
            gateway_session: Some(gateway_session),
            target_session,
            stream,
            sftp,
            write_closed: false,
            finished: false,
        })
    }
}
