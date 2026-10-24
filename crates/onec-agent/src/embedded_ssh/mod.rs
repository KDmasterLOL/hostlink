//! Library-owned managed target SSH/SFTP server.
//!
//! This module is intentionally not wired into the default agent carrier yet. It provides the
//! product boundary used by Phase A validation and the later explicit runtime migration.

mod preflight;
mod sftp;

pub use preflight::preflight_embedded_ssh;

use russh::keys::ssh_key::authorized_keys::AuthorizedKeys;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

use sftp::SftpSession;

const HOST_KEY_MAX_BYTES: usize = 64 * 1024;
const AUTHORIZED_KEYS_MAX_BYTES: usize = 1024 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIRECT_TCP_CHANNELS: usize = 32;
const MAX_ACTIVE_SFTP_SESSIONS: usize = 8;
const MAX_PENDING_SESSION_CHANNELS: usize = 16;

/// Persistent identity and authorization inputs for one embedded target SSH server.
#[derive(Clone, Debug)]
pub struct EmbeddedSshConfig {
    expected_user: String,
    host_key_path: PathBuf,
    authorized_keys_path: PathBuf,
}

impl EmbeddedSshConfig {
    /// Creates a server configuration backed by the existing installer-owned key files.
    pub fn new(
        expected_user: impl Into<String>,
        host_key_path: impl Into<PathBuf>,
        authorized_keys_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            expected_user: expected_user.into(),
            host_key_path: host_key_path.into(),
            authorized_keys_path: authorized_keys_path.into(),
        }
    }

    /// Validates the username, host-key privacy/format and enrolled controller authorization set.
    pub fn validate(&self) -> io::Result<()> {
        self.prepare().map(drop)
    }

    pub(crate) fn prepare(&self) -> io::Result<PreparedEmbeddedSshConfig> {
        let expected_user = self.expected_user.trim();
        if expected_user.is_empty() {
            return Err(invalid_data("embedded SSH expected user must not be empty"));
        }
        Ok(PreparedEmbeddedSshConfig {
            expected_user: Arc::<str>::from(expected_user),
            host_key: load_host_key(&self.host_key_path)?,
            authorized_keys: Arc::new(load_authorized_keys(&self.authorized_keys_path)?),
        })
    }
}

pub(crate) struct PreparedEmbeddedSshConfig {
    expected_user: Arc<str>,
    host_key: PrivateKey,
    authorized_keys: Arc<Vec<PublicKey>>,
}

#[derive(Clone)]
struct EmbeddedServer {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
}

struct EmbeddedSession {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

/// Serves authenticated SSH/SFTP traffic on an already-bound loopback listener until shutdown.
///
/// The listener is supplied by the caller so binding policy and readiness are explicit. Existing
/// agent runtime wiring remains unchanged until the migration phase deliberately calls this API.
pub async fn serve_until<F>(
    listener: tokio::net::TcpListener,
    config: EmbeddedSshConfig,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        return Err(invalid_data(format!(
            "embedded SSH listener must be loopback-only, got {address}"
        )));
    }

    let prepared = config.prepare()?;
    serve_prepared_until(listener, prepared, shutdown).await
}

pub(crate) async fn serve_prepared_until<F>(
    listener: tokio::net::TcpListener,
    prepared: PreparedEmbeddedSshConfig,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        return Err(invalid_data(format!(
            "embedded SSH listener must be loopback-only, got {address}"
        )));
    }

    let server_config = Arc::new(russh::server::Config {
        keys: vec![prepared.host_key],
        nodelay: true,
        ..Default::default()
    });
    let mut server = EmbeddedServer {
        expected_user: prepared.expected_user,
        authorized_keys: prepared.authorized_keys,
        forward_slots: Arc::new(Semaphore::new(MAX_DIRECT_TCP_CHANNELS)),
        sftp_slots: Arc::new(Semaphore::new(MAX_ACTIVE_SFTP_SESSIONS)),
    };

    let running = server.run_on_socket(server_config, &listener);
    let handle = running.handle();
    tokio::pin!(running);
    tokio::pin!(shutdown);

    tokio::select! {
        result = &mut running => result,
        () = &mut shutdown => {
            handle.shutdown("onec-agent embedded SSH shutdown".to_owned());
            tokio::time::timeout(SHUTDOWN_GRACE, &mut running)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "embedded SSH shutdown timed out"))?
        }
    }
}

impl russh::server::Server for EmbeddedServer {
    type Handler = EmbeddedSession;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        EmbeddedSession {
            expected_user: self.expected_user.clone(),
            authorized_keys: self.authorized_keys.clone(),
            forward_slots: self.forward_slots.clone(),
            sftp_slots: self.sftp_slots.clone(),
            session_channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl EmbeddedSession {
    fn accepts(&self, user: &str, public_key: &PublicKey) -> bool {
        user == self.expected_user.as_ref()
            && self.authorized_keys.iter().any(|allowed| {
                allowed.algorithm() == public_key.algorithm()
                    && allowed.key_data() == public_key.key_data()
            })
    }

    async fn take_session_channel(&self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        self.session_channels.lock().await.remove(&channel_id)
    }

    async fn discard_session_channel(&self, channel_id: ChannelId) {
        self.session_channels.lock().await.remove(&channel_id);
    }
}

impl russh::server::Handler for EmbeddedSession {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.accepts(user, public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.accepts(user, public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if host_to_connect.trim().is_empty()
            || port_to_connect == 0
            || port_to_connect > u16::MAX as u32
        {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        let Ok(forward_slot) = self.forward_slots.clone().try_acquire_owned() else {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        };
        let connect = tokio::net::TcpStream::connect((host_to_connect, port_to_connect as u16));
        let Ok(Ok(mut target)) = tokio::time::timeout(DIRECT_TCP_CONNECT_TIMEOUT, connect).await
        else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };

        reply.accept().await;
        tokio::spawn(async move {
            let _forward_slot = forward_slot;
            let mut ssh = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut ssh, &mut target).await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut ssh).await;
        });
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut session_channels = self.session_channels.lock().await;
        if session_channels.len() >= MAX_PENDING_SESSION_CHANNELS {
            drop(session_channels);
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        session_channels.insert(channel.id(), channel);
        drop(session_channels);
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.discard_session_channel(channel).await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            self.discard_session_channel(channel_id).await;
            session.channel_failure(channel_id)?;
            return Ok(());
        }

        let Some(channel) = self.take_session_channel(channel_id).await else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        let Ok(session_slot) = self.sftp_slots.clone().try_acquire_owned() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        session.channel_success(channel_id)?;
        russh_sftp::server::run(channel.into_stream(), SftpSession::new(session_slot)).await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.discard_session_channel(channel).await;
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.discard_session_channel(channel).await;
        session.channel_failure(channel)?;
        Ok(())
    }
}

fn load_host_key(path: &Path) -> io::Result<PrivateKey> {
    load_private_ed25519_key(path, "embedded SSH host key")
}

fn load_private_ed25519_key(path: &Path, purpose: &str) -> io::Result<PrivateKey> {
    hostlink_core::validate_private_file(path).map_err(io::Error::other)?;
    let bytes = hostlink_core::read_file_bounded(path, HOST_KEY_MAX_BYTES)?;
    let key = PrivateKey::from_openssh(&bytes)
        .map_err(|error| invalid_data(format!("invalid {purpose}: {error}")))?;
    if key.is_encrypted() {
        return Err(invalid_data(format!(
            "{purpose} must be unencrypted for unattended agent startup"
        )));
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid_data(format!(
            "{purpose} must be Ed25519, got {}",
            key.algorithm()
        )));
    }
    Ok(key)
}

fn load_public_ed25519_key(path: &Path, purpose: &str) -> io::Result<PublicKey> {
    let bytes = hostlink_core::read_file_bounded(path, HOST_KEY_MAX_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| invalid_data(format!("{purpose} is not UTF-8: {error}")))?;
    let key = PublicKey::from_openssh(text.trim())
        .map_err(|error| invalid_data(format!("invalid {purpose}: {error}")))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid_data(format!(
            "{purpose} must be Ed25519, got {}",
            key.algorithm()
        )));
    }
    Ok(key)
}

fn load_authorized_keys(path: &Path) -> io::Result<Vec<PublicKey>> {
    let bytes = hostlink_core::read_file_bounded(path, AUTHORIZED_KEYS_MAX_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        invalid_data(format!("authorized controller keys are not UTF-8: {error}"))
    })?;
    let mut keys = Vec::new();

    for entry in AuthorizedKeys::new(text) {
        let entry = entry
            .map_err(|error| invalid_data(format!("invalid authorized controller key: {error}")))?;
        if !entry.config_opts().is_empty() {
            return Err(invalid_data(
                "embedded SSH authorized controller keys must not use sshd-specific options",
            ));
        }
        let key = entry.public_key();
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(invalid_data(format!(
                "embedded SSH authorized controller key must be Ed25519, got {}",
                key.algorithm()
            )));
        }
        keys.push(key.clone());
    }

    if keys.is_empty() {
        return Err(invalid_data(
            "embedded SSH requires at least one authorized controller key",
        ));
    }
    Ok(keys)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests;
