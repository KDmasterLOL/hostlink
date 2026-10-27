#![allow(unused_imports)]
use super::config::{PreparedEmbeddedSshConfig, invalid_data, prepare, validate_jobs_root};
use super::jobs::{JobRuntime, handle_job_channel};
use super::*;

struct EmbeddedServer {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
    exec_slots: Arc<Semaphore>,
    exec_shutdown: processkit::CancellationToken,
    jobs: Arc<JobRuntime>,
    connection_slots: Arc<Semaphore>,
}

struct EmbeddedSession {
    expected_user: Arc<str>,
    authorized_keys: Arc<Vec<PublicKey>>,
    forward_slots: Arc<Semaphore>,
    sftp_slots: Arc<Semaphore>,
    exec_slots: Arc<Semaphore>,
    exec_shutdown: processkit::CancellationToken,
    jobs: Arc<JobRuntime>,
    _connection_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    active_exec: Arc<std::sync::Mutex<HashMap<ChannelId, processkit::CancellationToken>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    authenticated_controller: Option<String>,
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
    let store = DurableStore::open(&jobs_root).await?;
    let runner = store.acquire_runner()?;
    store.recover_nonterminal().await?;
    let jobs = Arc::new(JobRuntime {
        store,
        _runner: runner,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
        active_jobs: std::sync::Mutex::new(HashMap::new()),
    });
    if config.gateway.is_none() {
        return serve_prepared_until(listener, prepared, jobs, shutdown).await;
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
        jobs.clone(),
        cancellation.clone().cancelled_owned(),
    ));
    let mut tunnel = Box::pin(crate::tunnel::run(
        config,
        tunnel_cancellation.cancelled_owned(),
    ));
    tokio::pin!(shutdown_signal);
    tokio::select! {
        result = &mut server => {
            cancellation.cancel();
            // Keep polling the tunnel until its sessions and forwards shut down.
            result.and(tunnel.await)
        },
        result = &mut tunnel => {
            let expected_shutdown = cancellation.is_cancelled();
            cancellation.cancel();
            // A failed tunnel must still stop and drain Agent-owned process trees.
            server.await?;
            match result {
                Ok(()) if !expected_shutdown => Err(io::Error::other(
                    "reverse SSH tunnel ended before Agent shutdown",
                )),
                result => result,
            }
        },
        () = &mut shutdown_signal => {
            let (server_result, tunnel_result) = tokio::join!(&mut server, &mut tunnel);
            server_result.and(tunnel_result)
        },
    }
}

async fn serve_prepared_until<F>(
    listener: tokio::net::TcpListener,
    prepared: PreparedEmbeddedSshConfig,
    jobs: Arc<JobRuntime>,
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
        jobs: jobs.clone(),
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
    {
        let _start = jobs.start_lock.lock().await;
        jobs.accepting.store(false, Ordering::Release);
        jobs.shutdown.cancel();
    }
    let all_job_slots = jobs
        .slots
        .clone()
        .acquire_many_owned(MAX_ACTIVE_JOBS as u32);
    if tokio::time::timeout(SHUTDOWN_GRACE, all_job_slots)
        .await
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "durable job process trees did not finish during Agent shutdown",
        ));
    }
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
            jobs: self.jobs.clone(),
            _connection_slot: self.connection_slots.clone().try_acquire_owned().ok(),
            active_exec: Arc::new(std::sync::Mutex::new(HashMap::new())),
            session_channels: Arc::new(Mutex::new(HashMap::new())),
            authenticated_controller: None,
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
        if name != "sftp" && name != JOB_SUBSYSTEM {
            self.discard_session_channel(channel_id).await;
            fail_session_channel(channel_id, session)?;
            return Ok(());
        }

        let Some(channel) = self.take_session_channel(channel_id).await else {
            fail_session_channel(channel_id, session)?;
            return Ok(());
        };
        if name == "sftp" {
            let Some(owner) = self.authenticated_controller.clone() else {
                fail_session_channel(channel_id, session)?;
                return Ok(());
            };
            let Ok(session_slot) = self.sftp_slots.clone().try_acquire_owned() else {
                fail_session_channel(channel_id, session)?;
                return Ok(());
            };
            let artifacts = match self.jobs.store.artifacts(&owner) {
                Ok(artifacts) => artifacts,
                Err(_) => {
                    fail_session_channel(channel_id, session)?;
                    return Ok(());
                }
            };
            session.channel_success(channel_id)?;
            russh_sftp::server::run(
                channel.into_stream(),
                SftpSession::new(artifacts, session_slot),
            )
            .await;
        } else if let Some(owner) = self.authenticated_controller.clone() {
            let Ok(channel_slot) = self.jobs.channel_slots.clone().try_acquire_owned() else {
                fail_session_channel(channel_id, session)?;
                return Ok(());
            };
            session.channel_success(channel_id)?;
            let jobs = self.jobs.clone();
            tokio::spawn(async move {
                let _channel_slot = channel_slot;
                handle_job_channel(channel, jobs, owner).await;
            });
        } else {
            fail_session_channel(channel_id, session)?;
        }
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

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/wire/mod.rs"]
mod wire_tests;
