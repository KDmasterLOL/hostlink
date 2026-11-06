use super::config::PreparedEmbeddedSshConfig;
use crate::{exec, sftp::SftpSession};
use russh::{
    Channel, ChannelId, MethodKind, MethodSet,
    keys::{PublicKey, PublicKeyBase64},
    server::{Auth, Msg, Server as _, Session},
};
use sha2::{Digest as _, Sha256};
use std::{collections::HashMap, future::Future, io, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIRECT_TCP_CHANNELS: usize = 32;
const MAX_AUTHENTICATED_SESSIONS: usize = 32;
const MAX_ACTIVE_SFTP_SESSIONS: usize = 8;
const MAX_ACTIVE_EXEC_SESSIONS: usize = 4;
const MAX_PENDING_SESSION_CHANNELS: usize = 16;
const MAX_EXEC_COMMAND_BYTES: usize = 16 * 1024;

struct SharedState {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
    exec_slots: Arc<Semaphore>,
    exec_shutdown: processkit::CancellationToken,
    transfer_root: PathBuf,
    connection_slots: Arc<Semaphore>,
}

struct EmbeddedServer {
    shared: Arc<SharedState>,
}

struct EmbeddedSession {
    shared: Arc<SharedState>,
    _connection_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    active_exec: Arc<std::sync::Mutex<HashMap<ChannelId, processkit::CancellationToken>>>,
    session_channels: HashMap<ChannelId, Channel<Msg>>,
    pending_ptys: HashMap<ChannelId, PtyIntent>,
    authenticated_controller: Option<String>,
}

#[derive(Clone)]
struct PtyIntent {
    term: String,
    cols: u16,
    rows: u16,
}

pub(crate) async fn serve_prepared_until<F>(
    listener: tokio::net::TcpListener,
    prepared: PreparedEmbeddedSshConfig,
    transfer_root: PathBuf,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let server_config = Arc::new(russh::server::Config {
        keys: vec![prepared.host_key],
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        nodelay: true,
        ..Default::default()
    });
    let shared = Arc::new(SharedState {
        expected_user: prepared.expected_user,
        authorized_keys: prepared.authorized_keys,
        forward_slots: Arc::new(Semaphore::new(MAX_DIRECT_TCP_CHANNELS)),
        sftp_slots: Arc::new(Semaphore::new(MAX_ACTIVE_SFTP_SESSIONS)),
        exec_slots: Arc::new(Semaphore::new(MAX_ACTIVE_EXEC_SESSIONS)),
        exec_shutdown: processkit::CancellationToken::new(),
        transfer_root,
        connection_slots: Arc::new(Semaphore::new(MAX_AUTHENTICATED_SESSIONS)),
    });
    let exec_shutdown = shared.exec_shutdown.clone();
    let exec_slots = shared.exec_slots.clone();
    let mut server = EmbeddedServer { shared };

    let running = server.run_on_socket(server_config, &listener);
    let handle = running.handle();
    tokio::pin!(running);
    tokio::pin!(shutdown);

    let result = tokio::select! {
        result = &mut running => result,
        () = &mut shutdown => {
            handle.shutdown("HostLink embedded SSH shutdown".to_owned());
            match tokio::time::timeout(SHUTDOWN_GRACE, &mut running).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "embedded SSH shutdown timed out")),
            }
        }
    };
    exec_shutdown.cancel();
    let slots = exec_slots.acquire_many_owned(MAX_ACTIVE_EXEC_SESSIONS as u32);
    let _permit = tokio::time::timeout(SHUTDOWN_GRACE, slots)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH exec shutdown timed out"))?
        .map_err(io::Error::other)?;
    result
}

impl russh::server::Server for EmbeddedServer {
    type Handler = EmbeddedSession;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        EmbeddedSession {
            _connection_slot: self
                .shared
                .connection_slots
                .clone()
                .try_acquire_owned()
                .ok(),
            shared: self.shared.clone(),
            active_exec: Arc::new(std::sync::Mutex::new(HashMap::new())),
            session_channels: HashMap::new(),
            pending_ptys: HashMap::new(),
            authenticated_controller: None,
        }
    }
}

impl EmbeddedSession {
    fn accepts(&self, user: &str, public_key: &PublicKey) -> bool {
        self._connection_slot.is_some()
            && user == self.shared.expected_user.as_ref()
            && self.shared.authorized_keys.iter().any(|allowed| {
                allowed.algorithm() == public_key.algorithm()
                    && allowed.key_data() == public_key.key_data()
            })
    }

    fn take_session_channel(&mut self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        self.pending_ptys.remove(&channel_id);
        self.session_channels.remove(&channel_id)
    }

    fn discard_session_channel(&mut self, channel_id: ChannelId) {
        self.session_channels.remove(&channel_id);
        self.pending_ptys.remove(&channel_id);
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

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.accepts(user, public_key) {
            self.authenticated_controller = Some(format!(
                "{:x}",
                Sha256::digest(public_key.public_key_bytes())
            ));
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
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

        let Ok(forward_slot) = self.shared.forward_slots.clone().try_acquire_owned() else {
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
        if self.session_channels.len() >= MAX_PENDING_SESSION_CHANNELS {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        self.session_channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.cancel_exec(channel);
        self.discard_session_channel(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            self.discard_session_channel(channel_id);
            fail_session_channel(channel_id, session)?;
            return Ok(());
        }
        let Some(channel) = self.take_session_channel(channel_id) else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        let Some(owner) = self.authenticated_controller.as_deref() else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        let Ok(slot) = self.shared.sftp_slots.clone().try_acquire_owned() else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        let Ok(transfer) = SftpSession::new(&self.shared.transfer_root, owner, slot) else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        russh_sftp::server::run(channel.into_stream(), transfer).await;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.authenticated_controller.is_none() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(pty) = self.pending_ptys.remove(&channel) else {
            // Keep the channel available for a correctly ordered PTY + shell request.
            session.channel_failure(channel)?;
            return Ok(());
        };
        if !self.session_channels.contains_key(&channel)
            || self
                .active_exec
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&channel)
        {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Ok(slot) = self.shared.exec_slots.clone().try_acquire_owned() else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let command = match exec::prepare_shell(&pty.term, pty.cols, pty.rows) {
            Ok(command) => command,
            Err(_) => {
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        let Some(channel_handle) = self.take_session_channel(channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let cancellation = self.shared.exec_shutdown.child_token();
        self.active_exec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(channel, cancellation.clone());
        session.channel_success(channel)?;
        let active_exec = self.active_exec.clone();
        tokio::spawn(async move {
            let _slot = slot;
            exec::run_shell(channel_handle, command, cancellation).await;
            active_exec
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&channel);
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let valid_term = !term.is_empty()
            && term.len() <= 64
            && term.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        if self.authenticated_controller.is_none()
            || !self.session_channels.contains_key(&channel)
            || self.pending_ptys.contains_key(&channel)
            || !valid_term
            || !modes.is_empty()
            || col_width == 0
            || row_height == 0
            || col_width > i16::MAX as u32
            || row_height > i16::MAX as u32
        {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.pending_ptys.insert(
            channel,
            PtyIntent {
                term: term.to_owned(),
                cols: col_width as u16,
                rows: row_height as u16,
            },
        );
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // ProcessKit's live process handle is consumed by drain(), so this slice
        // cannot safely route a later resize. Refuse instead of claiming success.
        session.channel_failure(channel)?;
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
                self.discard_session_channel(channel);
                fail_session_channel(channel, session)?;
                return Ok(());
            }
        };
        let Ok(slot) = self.shared.exec_slots.clone().try_acquire_owned() else {
            self.discard_session_channel(channel);
            fail_session_channel(channel, session)?;
            return Ok(());
        };
        let Some(channel_handle) = self.take_session_channel(channel) else {
            fail_session_channel(channel, session)?;
            return Ok(());
        };
        let cancellation = self.shared.exec_shutdown.child_token();
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
