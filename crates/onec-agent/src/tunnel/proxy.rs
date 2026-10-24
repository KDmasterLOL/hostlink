//! TLS proxy process and byte-stream adaptation for the reverse SSH transport.

use crate::config::{SshGatewayEndpoint, SshTlsProxyConfig};
use crate::environment::AgentEnvironmentPolicy;
use hostlink_core::background_command;
use processkit::{ProcessStdin, RawOutputSink, RawSinkFuture, RunningProcess};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Error as IoError};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use super::SHUTDOWN_GRACE;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_TREE_EXIT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5);
const PROXY_TREE_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct ProxyStream {
    stdin: ProxyStdin,
    stdout: DuplexStream,
}

type ProxyStdinFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

struct ProxyStdin {
    stdin: Arc<tokio::sync::Mutex<Option<ProcessStdin>>>,
    pending_write: Option<ProxyStdinFuture>,
    pending_flush: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
    pending_shutdown: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

impl ProxyStdin {
    fn new(stdin: ProcessStdin) -> Self {
        Self {
            stdin: Arc::new(tokio::sync::Mutex::new(Some(stdin))),
            pending_write: None,
            pending_flush: None,
            pending_shutdown: None,
        }
    }
}

impl AsyncWrite for ProxyStdin {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            let stdin = Arc::clone(&self.stdin);
            let bytes = buf.to_vec();
            let len = bytes.len();
            self.pending_write = Some(Box::pin(async move {
                let mut stdin = stdin.lock().await;
                let stdin = stdin
                    .as_mut()
                    .ok_or_else(|| IoError::new(io::ErrorKind::BrokenPipe, "proxy stdin closed"))?;
                stdin.write(&bytes).await?;
                Ok(len)
            }));
        }
        let future = self
            .pending_write
            .as_mut()
            .expect("pending write was initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.pending_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush.is_none() {
            let stdin = Arc::clone(&self.stdin);
            self.pending_flush = Some(Box::pin(async move {
                let mut stdin = stdin.lock().await;
                let stdin = stdin
                    .as_mut()
                    .ok_or_else(|| IoError::new(io::ErrorKind::BrokenPipe, "proxy stdin closed"))?;
                stdin.flush().await
            }));
        }
        let future = self
            .pending_flush
            .as_mut()
            .expect("pending flush was initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.pending_flush = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_shutdown.is_none() {
            let stdin = Arc::clone(&self.stdin);
            self.pending_shutdown = Some(Box::pin(async move {
                let stdin = stdin.lock().await.take().ok_or_else(|| {
                    IoError::new(io::ErrorKind::BrokenPipe, "proxy stdin already closed")
                })?;
                stdin.finish().await
            }));
        }
        let future = self
            .pending_shutdown
            .as_mut()
            .expect("pending shutdown was initialized");
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.pending_shutdown = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(super) struct ProxyStdoutSink(Arc<tokio::sync::Mutex<DuplexStream>>);

impl ProxyStdoutSink {
    pub(super) fn new(writer: Arc<tokio::sync::Mutex<DuplexStream>>) -> Self {
        Self(writer)
    }
}

impl RawOutputSink for ProxyStdoutSink {
    fn write_chunk<'a>(&'a mut self, chunk: &'a [u8]) -> RawSinkFuture<'a> {
        Box::pin(async move { self.0.lock().await.write_all(chunk).await })
    }

    fn finish(&mut self) -> RawSinkFuture<'_> {
        Box::pin(async move { self.0.lock().await.shutdown().await })
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

pub(super) enum GatewayStream {
    Tcp(tokio::net::TcpStream),
    Proxy(ProxyStream),
}

pub(super) struct GatewayConnection {
    pub(super) stream: GatewayStream,
    pub(super) proxy: Option<RunningProcess>,
}

impl AsyncRead for GatewayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Proxy(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for GatewayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Proxy(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Proxy(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Proxy(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(super) async fn connect_gateway_stream(
    gateway: &SshGatewayEndpoint,
    environment: &AgentEnvironmentPolicy,
) -> io::Result<GatewayConnection> {
    if let Some(proxy) = &gateway.tls_proxy {
        let (stream, process) = spawn_tls_proxy(gateway, proxy, environment).await?;
        return Ok(GatewayConnection {
            stream: GatewayStream::Proxy(stream),
            proxy: Some(process),
        });
    }
    let stream = tokio::time::timeout(
        SSH_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((gateway.host.as_str(), gateway.port)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "timed out connecting to SSH gateway {}:{}",
                gateway.host, gateway.port
            ),
        )
    })??;
    stream.set_nodelay(true)?;
    Ok(GatewayConnection {
        stream: GatewayStream::Tcp(stream),
        proxy: None,
    })
}

pub(super) async fn spawn_tls_proxy(
    gateway: &SshGatewayEndpoint,
    proxy: &SshTlsProxyConfig,
    environment: &AgentEnvironmentPolicy,
) -> io::Result<(ProxyStream, RunningProcess)> {
    let argv = tls_proxy_command(gateway, proxy);
    let mut command = processkit::Command::new(argv.get_program())
        .args(argv.get_args())
        .create_no_window()
        .keep_stdin_open()
        .stdout(processkit::StdioMode::Piped)
        .stderr(processkit::StdioMode::Inherit);
    command = environment.apply_processkit_safe_base(command);

    const PROXY_STREAM_CAPACITY: usize = 64 * 1024;
    let (stdout_reader, stdout_writer) = tokio::io::duplex(PROXY_STREAM_CAPACITY);
    let stdout_writer = Arc::new(tokio::sync::Mutex::new(stdout_writer));
    let sink_writer = Arc::clone(&stdout_writer);
    command = command.stdout_raw_sink(move || ProxyStdoutSink::new(Arc::clone(&sink_writer)));

    let mut process = command.start().await.map_err(|error| {
        io::Error::other(format!(
            "failed to spawn owned TLS proxy {}: {error}",
            proxy.program.display()
        ))
    })?;
    let stdin = process
        .take_stdin()
        .ok_or_else(|| io::Error::other("ProcessKit TLS proxy did not expose its stdin pipe"))?;
    // Starting the non-consuming probe arms ProcessKit's live stdout pump. Its raw sink applies
    // backpressure through the bounded duplex writer until russh consumes those exact bytes.
    if let Err(error) = process.wait_for_tree_exit(Duration::ZERO).await
        && !matches!(error.reason(), processkit::ErrorReason::NotReady { .. })
    {
        return Err(io::Error::other(format!(
            "failed to start TLS proxy stdout pump: {error}"
        )));
    }
    Ok((
        ProxyStream {
            stdin: ProxyStdin::new(stdin),
            stdout: stdout_reader,
        },
        process,
    ))
}

pub(super) async fn stop_proxy_process(proxy: &mut Option<RunningProcess>) -> io::Result<()> {
    let Some(process) = proxy.take() else {
        return Ok(());
    };
    let tree = process
        .owned_tree_probe()
        .ok_or_else(|| io::Error::other("TLS proxy has no owned ProcessKit process tree"))?;
    #[cfg(target_os = "linux")]
    let initial_members = linux_initial_tree_member_identities(&tree)?;
    #[cfg(target_os = "linux")]
    let process_group = linux_proxy_process_group_identity(&process)?;
    process.shutdown(SHUTDOWN_GRACE).await.map_err(|error| {
        io::Error::other(format!("TLS proxy process-tree shutdown failed: {error}"))
    })?;
    #[cfg(target_os = "linux")]
    {
        wait_for_proxy_tree_exit(&tree, process_group, &initial_members).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        wait_for_proxy_tree_exit(&tree).await
    }
}

#[cfg(target_os = "linux")]
fn linux_initial_tree_member_identities(
    tree: &processkit::OwnedProcessTreeProbe,
) -> io::Result<HashMap<u32, u64>> {
    let mut identities = HashMap::new();
    for pid in tree.members().map_err(|error| {
        io::Error::other(format!(
            "cannot inspect TLS proxy initial process tree: {error}"
        ))
    })? {
        if let Some(stat) = read_linux_proc_stat(pid)? {
            identities.insert(pid, stat.start_time);
        }
    }
    Ok(identities)
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LinuxProxyProcessGroupIdentity {
    pgid: u32,
    session_id: u32,
    leader_start_time: u64,
    initial_members: HashMap<u32, u64>,
}

#[cfg(target_os = "linux")]
struct LinuxProcStat {
    pid: u32,
    state: char,
    process_group: u32,
    session_id: u32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn linux_proxy_process_group_identity(
    process: &RunningProcess,
) -> io::Result<Option<LinuxProxyProcessGroupIdentity>> {
    let pid = process
        .pid()
        .ok_or_else(|| io::Error::other("cannot identify an already-reaped TLS proxy process"))?;
    let root = read_linux_proc_stat(pid)?.ok_or_else(|| {
        io::Error::other(format!("TLS proxy PID {pid} disappeared before shutdown"))
    })?;
    if root.pid != pid {
        return Err(io::Error::other(format!(
            "TLS proxy PID identity changed before shutdown: expected {pid}, found {}",
            root.pid
        )));
    }

    let current = read_linux_proc_stat(std::process::id())?
        .ok_or_else(|| io::Error::other("cannot identify the Agent process group"))?;
    if root.process_group == current.process_group {
        // Linux cgroup containment does not change process groups. Its owned probe
        // enumerates the full cgroup, so do not inspect or adopt the Agent's group.
        return Ok(None);
    }
    if root.process_group != pid {
        return Err(io::Error::other(format!(
            "TLS proxy PID {pid} is in unexpected process group {}; refusing to treat it as owned",
            root.process_group
        )));
    }

    let initial_members = linux_process_group_members(root.process_group, root.session_id)?;
    if initial_members.get(&pid) != Some(&root.start_time) {
        return Err(io::Error::other(format!(
            "TLS proxy PID {pid} changed while capturing its process group"
        )));
    }

    Ok(Some(LinuxProxyProcessGroupIdentity {
        pgid: root.process_group,
        session_id: root.session_id,
        leader_start_time: root.start_time,
        initial_members,
    }))
}

#[cfg(target_os = "linux")]
fn linux_process_group_members(pgid: u32, session_id: u32) -> io::Result<HashMap<u32, u64>> {
    let mut members = HashMap::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(stat) = read_linux_proc_stat(pid)?
            && stat.process_group == pgid
            && stat.session_id == session_id
        {
            members.insert(pid, stat.start_time);
        }
    }
    Ok(members)
}

#[cfg(target_os = "linux")]
fn read_linux_proc_stat(pid: u32) -> io::Result<Option<LinuxProcStat>> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let stat = parse_linux_proc_stat(pid, &stat)?;
    if stat.pid != pid {
        return Err(invalid_linux_proc_stat(pid));
    }
    Ok(Some(stat))
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_stat(pid: u32, stat: &str) -> io::Result<LinuxProcStat> {
    let Some((identity, after_comm)) = stat.rsplit_once(')') else {
        return Err(invalid_linux_proc_stat(pid));
    };
    let parsed_pid = identity
        .split_whitespace()
        .next()
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| invalid_linux_proc_stat(pid))?;
    let fields = after_comm.split_whitespace().collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| invalid_linux_proc_stat(pid))?;
    let process_group = fields
        .get(2)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| invalid_linux_proc_stat(pid))?;
    let session_id = fields
        .get(3)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| invalid_linux_proc_stat(pid))?;
    let start_time = fields
        .get(19)
        .and_then(|field| field.parse::<u64>().ok())
        .ok_or_else(|| invalid_linux_proc_stat(pid))?;

    Ok(LinuxProcStat {
        pid: parsed_pid,
        state,
        process_group,
        session_id,
        start_time,
    })
}

#[cfg(target_os = "linux")]
fn invalid_linux_proc_stat(pid: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cannot parse /proc/{pid}/stat while confirming TLS proxy shutdown"),
    )
}

#[cfg(target_os = "linux")]
async fn wait_for_proxy_tree_exit(
    tree: &processkit::OwnedProcessTreeProbe,
    process_group: Option<LinuxProxyProcessGroupIdentity>,
    initial_members: &HashMap<u32, u64>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + PROXY_TREE_EXIT_CONFIRMATION_TIMEOUT;
    loop {
        let members = tree.members().map_err(|error| {
            io::Error::other(format!("cannot inspect TLS proxy process tree: {error}"))
        })?;
        if !linux_owned_proxy_tree_has_live_members(
            &members,
            process_group.as_ref(),
            initial_members,
        )? {
            return Ok(());
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS proxy process tree still has live members after shutdown",
            ));
        }
        tokio::time::sleep(PROXY_TREE_EXIT_POLL_INTERVAL.min(remaining)).await;
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_for_proxy_tree_exit(tree: &processkit::OwnedProcessTreeProbe) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + PROXY_TREE_EXIT_CONFIRMATION_TIMEOUT;
    loop {
        let members = tree.members().map_err(|error| {
            io::Error::other(format!("cannot inspect TLS proxy process tree: {error}"))
        })?;

        let has_live_members = !members.is_empty();

        if !has_live_members {
            return Ok(());
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS proxy process tree still has live members after shutdown",
            ));
        }
        tokio::time::sleep(PROXY_TREE_EXIT_POLL_INTERVAL.min(remaining)).await;
    }
}

#[cfg(target_os = "linux")]
fn linux_owned_proxy_tree_has_live_members(
    members: &[u32],
    process_group: Option<&LinuxProxyProcessGroupIdentity>,
    initial_members: &HashMap<u32, u64>,
) -> io::Result<bool> {
    if members.is_empty() && process_group.is_none() && initial_members.is_empty() {
        return Ok(false);
    }

    let process_group_is_current = match process_group {
        Some(identity) => linux_process_group_identity_is_current(identity)?,
        None => false,
    };

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_linux_proc_stat(pid) {
            Ok(Some(stat)) => stat,
            Ok(None) => continue,
            Err(error) => return Err(error),
        };
        let process_is_owned = members.contains(&pid)
            || initial_members.get(&pid) == Some(&stat.start_time)
            || process_group_is_current
                && process_group.is_some_and(|identity| {
                    stat.process_group == identity.pgid
                        && stat.session_id == identity.session_id
                        && identity.initial_members.get(&pid) == Some(&stat.start_time)
                });
        if process_is_owned && !matches!(stat.state, 'Z' | 'X' | 'x') {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn linux_process_group_identity_is_current(
    identity: &LinuxProxyProcessGroupIdentity,
) -> io::Result<bool> {
    match read_linux_proc_stat(identity.pgid)? {
        Some(leader) => Ok(leader.pid == identity.pgid
            && leader.process_group == identity.pgid
            && leader.session_id == identity.session_id
            && leader.start_time == identity.leader_start_time),
        // The group leader may have exited while descendants still keep its PGID
        // alive. Linux cannot reuse that PGID until the old group itself is gone.
        None => Ok(true),
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
pub(super) fn linux_proc_stat_is_live_owned_proxy_member(
    pid: u32,
    stat: &str,
    members: &[u32],
    process_group: Option<(u32, u32)>,
    initial_members: &[(u32, u64)],
) -> io::Result<bool> {
    let parsed = parse_linux_proc_stat(pid, stat)?;
    let belongs_to_owned_tree = members.contains(&pid)
        || initial_members
            .iter()
            .any(|(member_pid, start_time)| *member_pid == pid && *start_time == parsed.start_time)
        || process_group.is_some_and(|(pgid, session_id)| {
            parsed.process_group == pgid
                && parsed.session_id == session_id
                && initial_members.iter().any(|(member_pid, start_time)| {
                    *member_pid == pid && *start_time == parsed.start_time
                })
        });
    Ok(belongs_to_owned_tree && !matches!(parsed.state, 'Z' | 'X' | 'x'))
}

pub(super) fn tls_proxy_command(
    gateway: &SshGatewayEndpoint,
    proxy: &SshTlsProxyConfig,
) -> std::process::Command {
    let mut command = background_command(&proxy.program);
    command
        .arg("s_client")
        .arg("-quiet")
        .arg("-connect")
        .arg(format!("{}:{}", gateway.host, gateway.port))
        .arg("-servername")
        .arg(&proxy.server_name);
    if let Some(alpn) = &proxy.alpn {
        command.arg("-alpn").arg(alpn);
    }
    command
}
