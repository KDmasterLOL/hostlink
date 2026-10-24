//! TLS proxy process and byte-stream adaptation for the reverse SSH transport.

use crate::config::{SshGatewayEndpoint, SshTlsProxyConfig};
use crate::environment::AgentEnvironmentPolicy;
use onec_core::background_command;
use processkit::{ProcessStdin, RawOutputSink, RawSinkFuture, RunningProcess};
use std::future::Future;
use std::io::{self, Error as IoError};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use super::SHUTDOWN_GRACE;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    process.shutdown(SHUTDOWN_GRACE).await.map_err(|error| {
        io::Error::other(format!("TLS proxy process-tree shutdown failed: {error}"))
    })?;
    Ok(())
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
