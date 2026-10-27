//! Pinned russh connection setup, authentication, and bounded session cleanup.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use russh::{
    client::{self, Handle},
    keys::{self, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64},
};
use thiserror::Error;

use super::{
    gateway::{
        is_transient_gateway_connect_error, parse_pin, validate_gateway_routes, validate_user,
    },
    identity::load_identity,
};
use crate::HostSpec;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;

/// Errors returned by the pure Rust SSH client.
#[derive(Debug, Error)]
pub enum SshClientError {
    /// A target pin, user name, key, or command is invalid.
    #[error("invalid SSH configuration: {0}")]
    Invalid(String),
    /// SSH protocol or transport failed.
    #[error("SSH transport failed: {0}")]
    Russh(#[from] russh::Error),
    /// SSH key material could not be read or decoded.
    #[error("SSH key failed: {0}")]
    Key(#[from] russh::keys::Error),
    /// File or stream I/O failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// SFTP operation failed.
    #[error("SFTP failed: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    /// An SSH operation exceeded its bounded deadline.
    #[error("SSH operation timed out")]
    Timeout,
    /// Remote data exceeded the configured byte bound.
    #[error("remote transfer exceeded {MAX_TRANSFER_BYTES} bytes")]
    TransferTooLarge,
    /// The server closed the command channel without an exit status.
    #[error("remote command closed without an exit status")]
    MissingExitStatus,
    /// The server closed an exec channel before all standard input was sent.
    #[error("remote command closed before all standard input was sent")]
    EarlyChannelClose,
    /// A russh session did not stop within its cleanup deadline.
    #[error("SSH session cleanup could not be confirmed")]
    CleanupUnconfirmed,
}

pub(crate) struct PinHandler {
    pub(super) expected_key: PublicKey,
}

impl client::Handler for PinHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            return Ok(false);
        };
        Ok(key.public_key_bytes() == self.expected_key.public_key_bytes())
    }
}

/// An authenticated SSH connection to the selected host.
///
/// In gateway mode this value retains both session handles. Call
/// [`HostConnection::close`] to await bounded russh session cleanup.
pub struct HostConnection {
    pub(crate) session: Handle<PinHandler>,
    pub(crate) _gateway_session: Option<Handle<PinHandler>>,
}

impl HostConnection {
    #[cfg(test)]
    pub(crate) fn from_authenticated_session(session: Handle<PinHandler>) -> Self {
        Self {
            session,
            _gateway_session: None,
        }
    }

    /// Connects to a pinned host, optionally through an approved gateway.
    ///
    /// # Errors
    /// Returns an error for missing or malformed pins, invalid users, failed
    /// public-key authentication, rejected gateway forwarding, or timeout.
    pub async fn connect(spec: &HostSpec) -> Result<Self, SshClientError> {
        validate_user(&spec.user)?;
        let host_key = parse_pin(&spec.host_public_key)?;
        let identity = load_identity(&spec.identity)?;

        if let Some(gateway) = &spec.gateway {
            let routes = validate_gateway_routes(gateway)?;
            let mut connected = None;
            for (index, (address, user, identity, key)) in routes.into_iter().enumerate() {
                match connect_authenticated(address, &user, identity, key).await {
                    Ok(session) => {
                        connected = Some(session);
                        break;
                    }
                    Err(error)
                        if index + 1 < 1 + gateway.alternates.len()
                            && is_transient_gateway_connect_error(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            let gateway_session = connected.ok_or_else(|| {
                SshClientError::Invalid("no approved gateway route connected".into())
            })?;

            // The gateway's configured reverse listener is explicitly loopback-only.
            let channel = match tokio::time::timeout(
                CONNECT_TIMEOUT,
                gateway_session.channel_open_direct_tcpip(
                    "127.0.0.1",
                    u32::from(gateway.reverse_port),
                    "127.0.0.1",
                    0,
                ),
            )
            .await
            {
                Ok(Ok(channel)) => channel,
                Ok(Err(error)) => {
                    close_session(gateway_session, "gateway forwarding rejected").await?;
                    return Err(error.into());
                }
                Err(_) => {
                    close_session(gateway_session, "gateway forwarding timed out").await?;
                    return Err(SshClientError::Timeout);
                }
            };

            let target_session = match connect_stream_authenticated(
                channel.into_stream(),
                &spec.user,
                identity,
                host_key,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    close_session(gateway_session, "target connection failed").await?;
                    return Err(error);
                }
            };

            Ok(Self {
                session: target_session,
                _gateway_session: Some(gateway_session),
            })
        } else {
            let session =
                connect_authenticated(spec.endpoint, &spec.user, identity, host_key).await?;
            Ok(Self {
                session,
                _gateway_session: None,
            })
        }
    }

    /// Closes the target session and then its gateway session within a fixed deadline.
    ///
    /// # Errors
    /// Returns an error when russh cannot confirm that a session task stopped.
    pub async fn close(self) -> Result<(), SshClientError> {
        let target_result = close_session(self.session, "controller connection closed").await;
        let gateway_result = match self._gateway_session {
            Some(session) => close_session(session, "gateway connection closed").await,
            None => Ok(()),
        };
        target_result.and(gateway_result)
    }
}

async fn connect_authenticated(
    address: SocketAddr,
    user: &str,
    identity: russh::keys::PrivateKey,
    expected_key: PublicKey,
) -> Result<Handle<PinHandler>, SshClientError> {
    let config = Arc::new(client::Config::default());
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut session = tokio::time::timeout_at(
        deadline,
        client::connect(config, address, PinHandler { expected_key }),
    )
    .await
    .map_err(|_| SshClientError::Timeout)??;
    authenticate_with_cleanup(&mut session, user, identity, deadline).await?;
    Ok(session)
}

pub(crate) async fn connect_stream_authenticated<S>(
    stream: S,
    user: &str,
    identity: russh::keys::PrivateKey,
    expected_key: PublicKey,
) -> Result<Handle<PinHandler>, SshClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config::default());
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut session = tokio::time::timeout_at(
        deadline,
        client::connect_stream(config, stream, PinHandler { expected_key }),
    )
    .await
    .map_err(|_| SshClientError::Timeout)??;
    authenticate_with_cleanup(&mut session, user, identity, deadline).await?;
    Ok(session)
}

async fn authenticate_with_cleanup(
    session: &mut Handle<PinHandler>,
    user: &str,
    identity: russh::keys::PrivateKey,
    deadline: tokio::time::Instant,
) -> Result<(), SshClientError> {
    let result = tokio::time::timeout_at(deadline, authenticate(session, user, identity)).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            close_session_from_ref(session, "SSH authentication failed").await?;
            Err(error)
        }
        Err(_) => {
            close_session_from_ref(session, "SSH authentication timed out").await?;
            Err(SshClientError::Timeout)
        }
    }
}

async fn close_session(
    mut session: Handle<PinHandler>,
    description: &str,
) -> Result<(), SshClientError> {
    close_session_from_ref(&mut session, description).await
}

async fn close_session_from_ref(
    session: &mut Handle<PinHandler>,
    description: &str,
) -> Result<(), SshClientError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let _ = tokio::time::timeout_at(
        deadline,
        session.disconnect(russh::Disconnect::ByApplication, description, "en"),
    )
    .await;
    if tokio::time::timeout_at(deadline, session).await.is_err() {
        return Err(SshClientError::CleanupUnconfirmed);
    }
    Ok(())
}

async fn authenticate(
    session: &mut Handle<PinHandler>,
    user: &str,
    identity: russh::keys::PrivateKey,
) -> Result<(), SshClientError> {
    let result = session
        .authenticate_publickey(
            user.to_owned(),
            PrivateKeyWithHashAlg::new(Arc::new(identity), None),
        )
        .await?;
    if !result.success() {
        return Err(SshClientError::Invalid(
            "public-key authentication rejected".into(),
        ));
    }
    Ok(())
}
