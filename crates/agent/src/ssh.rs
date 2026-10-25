//! Authenticated embedded russh server for short exec, SFTP, and direct TCP forwarding.

use crate::{
    AgentConfig, exec,
    jobs::{self, Admission, JobId, JobOutput, JobSpec, JobState, JobStore},
    sftp::SftpSession,
};
use russh::keys::ssh_key::authorized_keys::AuthorizedKeys;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
const JOB_SUBSYSTEM: &str = "hostlink-jobs-v1";
const JOB_FRAME_MAX_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_JOBS: usize = 16;
const MAX_JOB_CHANNELS: usize = 32;
const JOB_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const JOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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
    jobs_root: PathBuf,
    jobs: Arc<JobRuntime>,
    _connection_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    active_exec: Arc<std::sync::Mutex<HashMap<ChannelId, processkit::CancellationToken>>>,
    session_channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    authenticated_controller: Option<String>,
}

struct JobRuntime {
    store: JobStore,
    start_lock: Mutex<()>,
    slots: Arc<Semaphore>,
    channel_slots: Arc<Semaphore>,
    accepting: AtomicBool,
    shutdown: processkit::CancellationToken,
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
    let store = JobStore::open(&jobs_root)?;
    store.recover_nonterminal()?;
    let jobs = Arc::new(JobRuntime {
        store,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
    });
    if config.gateway.is_none() {
        return serve_prepared_until(listener, prepared, jobs_root, jobs, shutdown).await;
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
        jobs.clone(),
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

async fn serve_prepared_until<F>(
    listener: tokio::net::TcpListener,
    prepared: PreparedEmbeddedSshConfig,
    jobs_root: PathBuf,
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
        jobs_root,
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
            jobs_root: self.jobs_root.clone(),
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

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum JobRequest {
    #[serde(rename = "start")]
    Start {
        version: u8,
        id: String,
        spec: JobSpec,
    },
    #[serde(rename = "status")]
    Status { version: u8, id: String },
    #[serde(rename = "output")]
    Output {
        version: u8,
        id: String,
        stream: JobOutput,
        offset: u64,
    },
}

#[derive(Serialize)]
struct JobResponse {
    version: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<JobState>,
    data_base64: Option<String>,
    next_offset: Option<u64>,
    eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

impl JobResponse {
    fn success(id: impl Into<String>, state: JobState) -> Self {
        Self {
            version: 1,
            ok: true,
            id: Some(id.into()),
            state: Some(state),
            data_base64: None,
            next_offset: None,
            eof: None,
            error: None,
        }
    }

    fn error(message: &'static str) -> Self {
        Self {
            version: 1,
            ok: false,
            id: None,
            state: None,
            data_base64: None,
            next_offset: None,
            eof: None,
            error: Some(message),
        }
    }
}

async fn handle_job_channel(channel: Channel<Msg>, runtime: Arc<JobRuntime>, owner: String) {
    let mut stream = channel.into_stream();
    let response =
        match tokio::time::timeout(JOB_REQUEST_TIMEOUT, read_job_frame(&mut stream)).await {
            Err(_) => JobResponse::error("jobs-v1 request timed out"),
            Ok(Err(_)) => JobResponse::error("invalid jobs-v1 frame"),
            Ok(Ok(bytes)) => match serde_json::from_slice::<JobRequest>(&bytes) {
                Ok(request) => handle_job_request(request, &runtime, &owner).await,
                Err(_) => JobResponse::error("malformed jobs-v1 request"),
            },
        };
    // An error reply is a separate, minimal jobs-v1 wire shape. Status/output
    // fields are present (null when unused) only for successful replies.
    let body = if response.ok {
        serde_json::to_vec(&response)
    } else {
        serde_json::to_vec(&serde_json::json!({
            "version": response.version,
            "ok": false,
            "error": response.error.unwrap_or("jobs-v1 request failed"),
        }))
    }
    .unwrap_or_else(|_| br#"{"version":1,"ok":false,"error":"response encoding failed"}"#.to_vec());
    if let Ok(size) = u32::try_from(body.len()) {
        let _ = stream.write_all(&size.to_be_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

async fn read_job_frame(stream: &mut russh::ChannelStream<Msg>) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > JOB_FRAME_MAX_BYTES {
        return Err(invalid_data("jobs-v1 request frame length is invalid"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let mut trailing = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut trailing)).await {
        Ok(Ok(0)) => Ok(body),
        _ => Err(invalid_data("jobs-v1 accepts exactly one request frame")),
    }
}

async fn handle_job_request(
    request: JobRequest,
    runtime: &Arc<JobRuntime>,
    owner: &str,
) -> JobResponse {
    let (version, id_text) = match &request {
        JobRequest::Start { version, id, .. }
        | JobRequest::Status { version, id }
        | JobRequest::Output { version, id, .. } => (*version, id.as_str()),
    };
    if version != 1 {
        return JobResponse::error("unsupported jobs-v1 version");
    }
    let Ok(id) = JobId::parse(id_text) else {
        return JobResponse::error("invalid job ID");
    };
    match request {
        JobRequest::Start { spec, .. } => {
            let _start = runtime.start_lock.lock().await;
            if !runtime.accepting.load(Ordering::Acquire) {
                return JobResponse::error("Agent is shutting down");
            }
            let admission = match runtime.store.admit(id, owner, &spec) {
                Ok(admission) => admission,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return JobResponse::error("job belongs to another controller");
                }
                Err(_) => return JobResponse::error("job admission failed"),
            };
            match admission {
                Admission::Existing(record) => {
                    JobResponse::success(record.id.to_string(), record.state)
                }
                Admission::Created(record) => {
                    if verify_job_source(&spec).is_err() {
                        let _ = runtime.store.transition(
                            id,
                            owner,
                            JobState::Prepared,
                            JobState::Failed,
                        );
                        return JobResponse::error("source executable verification failed");
                    }
                    let permit = match runtime.slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = runtime.store.transition(
                                id,
                                owner,
                                JobState::Prepared,
                                JobState::Failed,
                            );
                            return JobResponse::error("active job limit reached");
                        }
                    };
                    if runtime
                        .store
                        .transition(id, owner, JobState::Prepared, JobState::Running)
                        .is_err()
                    {
                        let _ = runtime.store.transition(
                            id,
                            owner,
                            JobState::Prepared,
                            JobState::Failed,
                        );
                        return JobResponse::error("job start reservation failed");
                    }
                    let runtime = runtime.clone();
                    let owner = owner.to_owned();
                    let response = JobResponse::success(id.to_string(), JobState::Running);
                    tokio::spawn(async move {
                        let _permit = permit;
                        run_job(runtime, owner, record).await;
                    });
                    response
                }
            }
        }
        JobRequest::Status { .. } => match runtime.store.lookup(id, owner) {
            Ok(record) => JobResponse::success(record.id.to_string(), record.state),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                JobResponse::error("job belongs to another controller")
            }
            Err(_) => JobResponse::error("job status unavailable"),
        },
        JobRequest::Output { stream, offset, .. } => {
            match runtime.store.read_output(id, owner, stream, offset) {
                Ok((data, next, eof)) => {
                    let Ok(record) = runtime.store.lookup(id, owner) else {
                        return JobResponse::error("job status unavailable");
                    };
                    let mut response = JobResponse::success(record.id.to_string(), record.state);
                    use base64::Engine as _;
                    response.data_base64 =
                        Some(base64::engine::general_purpose::STANDARD.encode(data));
                    response.next_offset = Some(next);
                    response.eof = Some(eof);
                    response
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    JobResponse::error("job belongs to another controller")
                }
                Err(_) => JobResponse::error("job output unavailable"),
            }
        }
    }
}

fn verify_job_source(spec: &JobSpec) -> io::Result<PathBuf> {
    if !Path::new(&spec.program).is_absolute() || spec.program.contains('\0') {
        return Err(invalid_data("job executable must be an absolute path"));
    }
    let program = Path::new(&spec.program);
    let metadata = std::fs::symlink_metadata(program)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            "job executable must be a regular non-symlink file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid_data("job executable must not be a reparse point"));
        }
        if !crate::exec::safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable jobs require a verified non-elevated, non-LocalSystem Windows user context",
            ));
        }
        jobs::validate_private_path(program, false)?;
        if let Some(parent) = program.parent() {
            jobs::validate_private_path(parent, true)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid_data("job executable has no execute permission"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(program)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(invalid_data("job executable must be a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_size() != opened_metadata.file_size()
            || metadata.last_write_time() != opened_metadata.last_write_time()
            || metadata.creation_time() != opened_metadata.creation_time()
        {
            return Err(invalid_data(
                "job executable path changed while opening for verification",
            ));
        }
    }
    #[cfg(windows)]
    let original_identity = windows_file_identity(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened_metadata.uid() != unsafe { libc::geteuid() }
            || opened_metadata.nlink() != 1
            || opened_metadata.permissions().mode() & 0o222 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job executable must be Agent-owned, singly linked and read-only",
            ));
        }
    }
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest_writer(&mut digest))?;
    if format!("{:x}", digest.finalize()) != spec.source_sha256 {
        return Err(invalid_data("job executable digest mismatch"));
    }
    let after_hash = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if after_hash.dev() != opened_metadata.dev()
            || after_hash.ino() != opened_metadata.ino()
            || after_hash.len() != opened_metadata.len()
            || after_hash.mtime() != opened_metadata.mtime()
            || after_hash.mtime_nsec() != opened_metadata.mtime_nsec()
            || after_hash.ctime() != opened_metadata.ctime()
            || after_hash.ctime_nsec() != opened_metadata.ctime_nsec()
            || path_after_hash.file_type().is_symlink()
            || path_after_hash.dev() != opened_metadata.dev()
            || path_after_hash.ino() != opened_metadata.ino()
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if path_after_hash.file_attributes() & 0x400 != 0
            || after_hash.file_size() != opened_metadata.file_size()
            || after_hash.last_write_time() != opened_metadata.last_write_time()
            || path_after_hash.file_size() != opened_metadata.file_size()
            || path_after_hash.last_write_time() != opened_metadata.last_write_time()
            || original_identity != windows_file_identity(&file)?
            || original_identity != windows_file_identity(&std::fs::File::open(program)?)?
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    // The open descriptor is hashed, then ProcessKit launches by pathname. Read-only ownership
    // checks reduce external mutation, but cannot pin the executed inode against a same-UID path
    // replacement between this check and exec; this is not an exec-by-fd guarantee.
    if let Some(cwd) = &spec.cwd {
        let metadata = std::fs::symlink_metadata(cwd)?;
        if !cwd.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid_data(
                "job working directory must be absolute and safe",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid_data("job working directory is a reparse point"));
            }
            jobs::validate_private_path(cwd, true)?;
        }
    }
    Ok(program.to_path_buf())
}

/// Stable Win32 replacement for nightly-only MetadataExt file_index and
/// volume_serial_number. GetFileInformationByHandle is present on NT6.1.
#[cfg(windows)]
fn windows_file_identity(file: &std::fs::File) -> io::Result<(u32, u64, u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is an open, owned File handle, and info points to a
    // correctly sized writable Win32 output structure.
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    let write_time = (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
        | u64::from(info.ftLastWriteTime.dwLowDateTime);
    // Ambiguous file identity or multiple hardlinks cannot establish
    // that this source is the single privately controlled executable.
    if index == 0 || info.nNumberOfLinks != 1 {
        return Err(invalid_data(
            "source-pinned Windows executable identity is ambiguous or multiply linked",
        ));
    }
    Ok((info.dwVolumeSerialNumber, index, size, write_time))
}

fn digest_writer<'a>(digest: &'a mut Sha256) -> impl io::Write + 'a {
    struct DigestWriter<'a>(&'a mut Sha256);
    impl io::Write for DigestWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    DigestWriter(digest)
}

async fn run_job(runtime: Arc<JobRuntime>, owner: String, record: crate::jobs::JobRecord) {
    let id = record.id;
    if verify_job_source(&record.spec).is_err() {
        let _ = runtime
            .store
            .transition(id, &owner, JobState::Running, JobState::Failed);
        return;
    }
    let (out, out_sync) = match open_job_output(&runtime, id, JobOutput::Stdout) {
        Ok(files) => files,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let (err, err_sync) = match open_job_output(&runtime, id, JobOutput::Stderr) {
        Ok(files) => files,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let overflowed = Arc::new(AtomicBool::new(false));
    let cancel = runtime.shutdown.child_token();
    let mut command = processkit::Command::new(&record.spec.program)
        .args(&record.spec.args)
        .stdin(processkit::Stdin::empty())
        .stdout_raw_tee(CappedOutputWriter::new(
            out,
            overflowed.clone(),
            cancel.clone(),
        ))
        .stderr_raw_tee(CappedOutputWriter::new(
            err,
            overflowed.clone(),
            cancel.clone(),
        ))
        .output_buffer(processkit::OutputBufferPolicy::bounded(256).with_max_bytes(64 * 1024))
        .timeout(JOB_TIMEOUT)
        .timeout_grace(Duration::from_secs(2))
        .kill_on_parent_death()
        .cancel_on(cancel);
    if let Some(cwd) = &record.spec.cwd {
        command = command.current_dir(cwd);
    }
    // ProcessKit owns timeout, cancellation and child cleanup. Windows uses its Job Object,
    // including kill-on-close for the complete process tree; Linux uses its private process group.
    let outcome = match command.start().await {
        Ok(child) => child.drain().await,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let sync_results =
        tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all())).await;
    let overflow = overflowed.load(Ordering::Acquire);
    let next = if runtime.shutdown.is_cancelled() {
        JobState::Interrupted
    } else if overflow
        || sync_results.is_err()
        || sync_results.is_ok_and(|(out, err)| out.is_err() || err.is_err())
    {
        JobState::Failed
    } else {
        match outcome {
            Ok(processkit::Outcome::Exited(code)) => JobState::Exited { code },
            Ok(
                processkit::Outcome::Signalled(_)
                | processkit::Outcome::TimedOut
                | processkit::Outcome::InactivityTimedOut,
            ) => JobState::Failed,
            Err(_) => JobState::Failed,
            _ => JobState::Failed,
        }
    };
    let _ = runtime
        .store
        .transition(id, &owner, JobState::Running, next);
}

fn open_job_output(
    runtime: &JobRuntime,
    id: JobId,
    stream: JobOutput,
) -> io::Result<(tokio::fs::File, std::fs::File)> {
    let file = jobs::open_output_append(&runtime.store.output_path(id, stream))?;
    let sync_file = file.try_clone()?;
    Ok((tokio::fs::File::from_std(file), sync_file))
}

struct CappedOutputWriter {
    file: tokio::fs::File,
    written: u64,
    overflowed: Arc<AtomicBool>,
    cancel: processkit::CancellationToken,
}

impl CappedOutputWriter {
    fn new(
        file: tokio::fs::File,
        overflowed: Arc<AtomicBool>,
        cancel: processkit::CancellationToken,
    ) -> Self {
        Self {
            file,
            written: 0,
            overflowed,
            cancel,
        }
    }
}

impl AsyncWrite for CappedOutputWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let remaining = jobs::MAX_JOB_OUTPUT_BYTES.saturating_sub(self.written) as usize;
        if remaining == 0 && !buffer.is_empty() {
            self.overflowed.store(true, Ordering::Release);
            self.cancel.cancel();
            return Poll::Ready(Err(io::Error::other("job output exceeds 8 MiB limit")));
        }
        let allowed = buffer.len().min(remaining);
        match Pin::new(&mut self.file).poll_write(cx, &buffer[..allowed]) {
            Poll::Ready(Ok(written)) => {
                self.written += written as u64;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

fn fail_session_channel(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    session.channel_failure(channel)?;
    session.close(channel)
}

#[cfg(all(test, unix))]
mod job_source_tests {
    use super::{JobSpec, verify_job_source};
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn job_source_rejects_digest_mismatch_and_symlink() {
        let temp = tempfile::tempdir().expect("private source fixture");
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect source fixture");
        let source = temp.path().join("worker");
        std::fs::copy(std::env::current_exe().expect("test executable"), &source)
            .expect("copy source fixture");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500))
            .expect("make source immutable to group and others");
        let digest = format!(
            "{:x}",
            Sha256::digest(std::fs::read(&source).expect("source bytes"))
        );
        let mut spec = JobSpec {
            program: source.to_string_lossy().into_owned(),
            args: Vec::new(),
            cwd: None,
            source_sha256: "0".repeat(64),
        };
        assert!(
            verify_job_source(&spec).is_err(),
            "wrong pinned digest fails closed"
        );

        spec.source_sha256 = digest;
        let link = temp.path().join("worker-link");
        std::os::unix::fs::symlink(&source, &link).expect("create source symlink");
        spec.program = link.to_string_lossy().into_owned();
        assert!(
            verify_job_source(&spec).is_err(),
            "symlink source fails closed"
        );
    }
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

#[cfg(all(test, target_os = "linux"))]
mod durable_job_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn prepared_job(
        args: Vec<String>,
        cwd: &Path,
    ) -> (
        tempfile::TempDir,
        Arc<JobRuntime>,
        String,
        crate::jobs::JobRecord,
    ) {
        let temp = tempfile::tempdir().expect("private test root");
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let jobs_root = temp.path().join("jobs");
        std::fs::create_dir(&jobs_root).expect("create job store root");
        std::fs::set_permissions(&jobs_root, std::fs::Permissions::from_mode(0o700))
            .expect("private job store mode");
        let source = temp.path().join("pinned-sh");
        std::fs::copy(
            std::fs::canonicalize("/bin/sh").expect("resolve shell"),
            &source,
        )
        .expect("stage executable");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500))
            .expect("make executable read-only");
        let spec = JobSpec {
            program: source.display().to_string(),
            args,
            cwd: Some(cwd.to_path_buf()),
            source_sha256: format!(
                "{:x}",
                Sha256::digest(std::fs::read(&source).expect("hash executable"))
            ),
        };
        let store = JobStore::open(jobs_root).expect("open private store");
        let id = JobId::new();
        let owner = "d".repeat(64);
        let Admission::Created(_) = store.admit(id, &owner, &spec).expect("admit job") else {
            panic!("fresh job ID is newly admitted");
        };
        let record = store
            .transition(id, &owner, JobState::Prepared, JobState::Running)
            .expect("reserve worker state");
        let runtime = Arc::new(JobRuntime {
            store,
            start_lock: Mutex::new(()),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
            channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
            accepting: AtomicBool::new(true),
            shutdown: processkit::CancellationToken::new(),
        });
        let _ = record;
        let record = runtime
            .store
            .lookup(id, &owner)
            .expect("read admitted record");
        (temp, runtime, owner, record)
    }

    fn linux_process_is_running(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some((_, fields)) = stat.rsplit_once(')') else {
            return false;
        };
        !fields.trim_start().starts_with("Z ")
    }

    #[tokio::test]
    async fn agent_shutdown_cancels_the_owned_process_tree() {
        assert_eq!(
            processkit::Command::kill_on_parent_death_scope(),
            processkit::ParentDeathCleanup::DirectChildOnly,
            "Linux abrupt parent death is documented as direct-child-only"
        );
        let temp = tempfile::tempdir().expect("working directory");
        let pid_path = temp.path().join("descendant-pid");
        let script = format!("sleep 300 & echo $! > '{}'; wait", pid_path.display());
        let (temp_root, runtime, owner, record) =
            prepared_job(vec!["-c".into(), script], temp.path()).await;
        let id = record.id;
        let worker = tokio::spawn(run_job(runtime.clone(), owner.clone(), record));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pid_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant pid file appears");
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .expect("read descendant pid")
            .trim()
            .parse()
            .expect("valid descendant pid");

        runtime.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker teardown deadline")
            .expect("worker task");
        assert_eq!(
            runtime
                .store
                .lookup(id, &owner)
                .expect("read final state")
                .state,
            JobState::Interrupted
        );
        for _ in 0..100 {
            if !linux_process_is_running(pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !linux_process_is_running(pid),
            "owned descendant was reaped"
        );
        drop(temp_root);
    }

    #[tokio::test]
    async fn output_overflow_kills_the_tree_and_never_records_zero_exit() {
        let temp = tempfile::tempdir().expect("working directory");
        let (temp_root, runtime, owner, record) = prepared_job(
            vec!["-c".into(), "head -c 8388609 /dev/zero".into()],
            temp.path(),
        )
        .await;
        let id = record.id;
        tokio::time::timeout(
            Duration::from_secs(10),
            run_job(runtime.clone(), owner.clone(), record),
        )
        .await
        .expect("overflow teardown deadline");
        assert_eq!(
            runtime
                .store
                .lookup(id, &owner)
                .expect("read final state")
                .state,
            JobState::Failed
        );
        assert_eq!(
            std::fs::metadata(runtime.store.output_path(id, JobOutput::Stdout))
                .expect("bounded stdout file")
                .len(),
            jobs::MAX_JOB_OUTPUT_BYTES
        );
        assert!(
            !matches!(
                runtime.store.lookup(id, &owner).expect("read status").state,
                JobState::Exited { code: 0 }
            ),
            "an over-limit stream cannot be reported as successful"
        );
        drop(temp_root);
    }
}
