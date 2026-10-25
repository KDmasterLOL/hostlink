//! Authenticated embedded russh server for short exec, SFTP, and direct TCP forwarding.

use crate::{AgentConfig, exec, sftp::SftpSession};
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

const HOST_KEY_MAX_BYTES: usize = 64 * 1024;
const AUTHORIZED_KEYS_MAX_BYTES: usize = 1024 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIRECT_TCP_CHANNELS: usize = 32;
const MAX_AUTHENTICATED_SESSIONS: usize = 32;
const MAX_ACTIVE_SFTP_SESSIONS: usize = 8;
const MAX_ACTIVE_EXEC_SESSIONS: usize = 4;
const MAX_PENDING_SESSION_CHANNELS: usize = 16;
const MAX_EXEC_COMMAND_BYTES: usize = 16 * 1024;

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
    exec_slots: Arc<Semaphore>,
    exec_shutdown: processkit::CancellationToken,
    jobs_root: PathBuf,
    connection_slots: Arc<Semaphore>,
}

struct EmbeddedSession {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
    exec_slots: Arc<Semaphore>,
    exec_shutdown: processkit::CancellationToken,
    jobs_root: PathBuf,
    _connection_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    active_exec: Arc<std::sync::Mutex<HashMap<ChannelId, processkit::CancellationToken>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

/// Serves authenticated SSH/SFTP traffic on the configured loopback listener until shutdown.
pub async fn serve<F>(config: &AgentConfig, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    config.validate()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    serve_on(listener, config, shutdown).await
}

/// Serves on a listener that the caller has already bound.
///
/// Prebinding makes the endpoint ready before the serving task is scheduled, which is useful for
/// deterministic startup coordination and tests.
pub async fn serve_on<F>(
    listener: tokio::net::TcpListener,
    config: &AgentConfig,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    config.validate()?;
    let bound = listener.local_addr()?;
    if bound != config.listen || !bound.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "prebound SSH listener must match configured loopback address",
        ));
    }
    let prepared = prepare(config)?;
    let jobs_root = validate_jobs_root(&config.jobs_root)?;
    if config.gateway.is_none() {
        return serve_prepared_until(listener, prepared, jobs_root, shutdown).await;
    }
    let cancellation = processkit::CancellationToken::new();
    let shutdown_signal = async {
        shutdown.await;
        cancellation.cancel();
    };
    let tunnel_cancellation = cancellation.clone();
    let mut server = Box::pin(serve_prepared_until(
        listener,
        prepared,
        jobs_root,
        cancellation.clone().cancelled_owned(),
    ));
    let mut tunnel = Box::pin(crate::tunnel::run(
        config,
        tunnel_cancellation.cancelled_owned(),
    ));
    tokio::pin!(shutdown_signal);
    tokio::select! {
        result = &mut server => result,
        result = &mut tunnel => {
            if cancellation.is_cancelled() { server.await } else { result }
        },
        () = &mut shutdown_signal => tokio::select! {
            result = &mut server => result,
            result = &mut tunnel => result,
        },
    }
}

pub(crate) async fn serve_prepared_until<F>(
    listener: tokio::net::TcpListener,
    prepared: PreparedEmbeddedSshConfig,
    jobs_root: PathBuf,
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
        exec_slots: Arc::new(Semaphore::new(MAX_ACTIVE_EXEC_SESSIONS)),
        exec_shutdown: processkit::CancellationToken::new(),
        jobs_root,
        connection_slots: Arc::new(Semaphore::new(MAX_AUTHENTICATED_SESSIONS)),
    };
    let exec_shutdown = server.exec_shutdown.clone();

    let running = server.run_on_socket(server_config, &listener);
    let handle = running.handle();
    tokio::pin!(running);
    tokio::pin!(shutdown);

    let result = tokio::select! {
        result = &mut running => result,
        () = &mut shutdown => {
            handle.shutdown("onec-agent embedded SSH shutdown".to_owned());
            match tokio::time::timeout(SHUTDOWN_GRACE, &mut running).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "embedded SSH shutdown timed out",
                )),
            }
        }
    };
    exec_shutdown.cancel();
    result
}

impl russh::server::Server for EmbeddedServer {
    type Handler = EmbeddedSession;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        EmbeddedSession {
            expected_user: self.expected_user.clone(),
            authorized_keys: self.authorized_keys.clone(),
            forward_slots: self.forward_slots.clone(),
            sftp_slots: self.sftp_slots.clone(),
            exec_slots: self.exec_slots.clone(),
            exec_shutdown: self.exec_shutdown.clone(),
            jobs_root: self.jobs_root.clone(),
            _connection_slot: self.connection_slots.clone().try_acquire_owned().ok(),
            active_exec: Arc::new(std::sync::Mutex::new(HashMap::new())),
            session_channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl EmbeddedSession {
    fn accepts(&self, user: &str, public_key: &PublicKey) -> bool {
        self._connection_slot.is_some()
            && user == self.expected_user.as_ref()
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

    fn cancel_exec(&self, channel_id: ChannelId) {
        let cancellation = self
            .active_exec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&channel_id);
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }
}

impl Drop for EmbeddedSession {
    fn drop(&mut self) {
        let active = self
            .active_exec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for cancellation in active.values() {
            cancellation.cancel();
        }
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
        self.cancel_exec(channel);
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
            fail_session_channel(channel_id, session)?;
            return Ok(());
        }

        let Some(channel) = self.take_session_channel(channel_id).await else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        let Ok(session_slot) = self.sftp_slots.clone().try_acquire_owned() else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };

        session.channel_success(channel_id)?;
        russh_sftp::server::run(
            channel.into_stream(),
            SftpSession::new(self.jobs_root.clone(), session_slot),
        )
        .await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.discard_session_channel(channel).await;
        fail_session_channel(channel, session)?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.discard_session_channel(channel).await;
        fail_session_channel(channel, session)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = match exec::validate_command(data, MAX_EXEC_COMMAND_BYTES)
            .and_then(|command| exec::prepare_command(&command))
        {
            Ok(command) => command,
            Err(_) => {
                self.discard_session_channel(channel).await;
                fail_session_channel(channel, session)?;
                return Ok(());
            }
        };
        let Ok(slot) = self.exec_slots.clone().try_acquire_owned() else {
            self.discard_session_channel(channel).await;
            fail_session_channel(channel, session)?;
            return Ok(());
        };
        let Some(channel_handle) = self.take_session_channel(channel).await else {
            fail_session_channel(channel, session)?;
            return Ok(());
        };
        let cancellation = self.exec_shutdown.child_token();
        self.active_exec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(channel, cancellation.clone());
        session.channel_success(channel)?;

        let active_exec = self.active_exec.clone();
        tokio::spawn(async move {
            let _slot = slot;
            exec::run(channel_handle, command, cancellation).await;
            active_exec
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&channel);
        });
        Ok(())
    }
}

fn fail_session_channel(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    session.channel_failure(channel)?;
    session.close(channel)
}

fn load_host_key(path: &Path) -> io::Result<PrivateKey> {
    load_private_ed25519_key(path, "embedded SSH host key")
}

fn load_private_ed25519_key(path: &Path, purpose: &str) -> io::Result<PrivateKey> {
    validate_private_file(path)?;
    let bytes = read_bounded(path, HOST_KEY_MAX_BYTES)?;
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

fn load_authorized_keys(path: &Path) -> io::Result<Vec<PublicKey>> {
    let bytes = read_bounded(path, AUTHORIZED_KEYS_MAX_BYTES)?;
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

fn prepare(config: &AgentConfig) -> io::Result<PreparedEmbeddedSshConfig> {
    if config.user.trim().is_empty() {
        return Err(invalid_data("SSH user must not be empty"));
    }
    Ok(PreparedEmbeddedSshConfig {
        expected_user: Arc::<str>::from(config.user.trim()),
        host_key: load_host_key(&config.host_key)?,
        authorized_keys: Arc::new(load_authorized_keys(&config.authorized_keys)?),
    })
}
fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        return Err(invalid_data("SSH key input must be a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSH secret file permissions are not private",
            ));
        }
    }
    #[cfg(windows)]
    {
        validate_private_acl(path)?;
    }
    std::fs::read(path)
}

pub(crate) fn validate_private_path(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_data("private path must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private path is group/world accessible",
            ));
        }
    }
    #[cfg(windows)]
    validate_private_acl(path)?;
    Ok(())
}
fn validate_private_file(path: &Path) -> io::Result<()> {
    let _ = read_bounded(path, HOST_KEY_MAX_BYTES)?;
    Ok(())
}

fn validate_jobs_root(path: &Path) -> io::Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            "SFTP root must be an existing non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SFTP root must not be group/world accessible",
            ));
        }
    }
    #[cfg(windows)]
    {
        validate_private_acl(path)?;
    }
    std::fs::canonicalize(path)
}

#[cfg(windows)]
fn validate_private_acl(path: &Path) -> io::Result<()> {
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
    };
    use windows_permissions::{LocalBox, Sid};

    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )?;
    let current = windows_permissions::utilities::current_process_sid()?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private path owner must be the current Windows user",
        ));
    }
    let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private path DACL must be protected from inherited permissions",
        ));
    }
    let system: LocalBox<Sid> = "S-1-5-18".parse()?;
    let administrators: LocalBox<Sid> = "S-1-5-32-544".parse()?;
    let dacl = descriptor.dacl().ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "private path has no DACL")
    })?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "private path has an unreadable ACE",
            )
        })?;
        let allows = matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        );
        if !allows {
            continue;
        }
        let sid = ace.sid().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private path has an allow ACE without a verifiable SID",
            )
        })?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != administrators.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private path DACL grants access to an unexpected principal",
            ));
        }
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
