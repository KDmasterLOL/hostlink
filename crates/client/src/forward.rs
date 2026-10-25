//! SSH direct-tcpip forwarding over an authenticated target connection.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};

use crate::connect::{HostConnection, OPERATION_TIMEOUT, SshClientError};

const MAX_LOCAL_FORWARD_CONNECTIONS: usize = 16;
const FORWARD_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const FORWARD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// Bidirectional byte stream backed by an SSH direct-tcpip channel.
pub type ForwardStream = russh::ChannelStream<russh::client::Msg>;

impl HostConnection {
    /// Opens one direct-tcpip channel to a destination reachable from this SSH peer.
    ///
    /// # Errors
    /// Returns an error if the peer rejects forwarding or channel setup times out.
    pub async fn open_forward(
        &self,
        destination: SocketAddr,
    ) -> Result<ForwardStream, SshClientError> {
        let channel = tokio::time::timeout(
            OPERATION_TIMEOUT,
            self.session.channel_open_direct_tcpip(
                destination.ip().to_string(),
                u32::from(destination.port()),
                "127.0.0.1",
                0,
            ),
        )
        .await
        .map_err(|_| SshClientError::Timeout)??;
        Ok(channel.into_stream())
    }
}

/// A running loopback-only TCP forward backed by one pinned SSH connection.
#[must_use = "keep the forward handle alive and call shutdown to join its tasks"]
pub struct ForwardServer {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), SshClientError>>>,
}

impl ForwardServer {
    /// The actual local address, including an OS-assigned port when `0` was requested.
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting connections, cancels active streams, joins workers and closes SSH.
    ///
    /// # Errors
    /// Returns an error if a worker panicked, SSH cleanup failed, or shutdown exceeded its deadline.
    pub async fn shutdown(mut self) -> Result<(), SshClientError> {
        let _ = self.stop.send(true);
        let Some(mut task) = self.task.take() else {
            return Err(SshClientError::CleanupUnconfirmed);
        };
        match tokio::time::timeout(FORWARD_SHUTDOWN_TIMEOUT, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(SshClientError::CleanupUnconfirmed),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(SshClientError::CleanupUnconfirmed)
            }
        }
    }
}

impl Drop for ForwardServer {
    fn drop(&mut self) {
        // Dropping a handle still signals cancellation; the owned task observes it,
        // drains its bounded worker set and closes the SSH session.
        let _ = self.stop.send(true);
    }
}

/// Starts a bounded local TCP proxy through an already authenticated SSH connection.
///
/// The listener must be on a loopback address. Port zero is accepted for callers
/// that need an OS-assigned ephemeral port.
///
/// # Errors
/// Returns an error for non-loopback/zero-port binds, listener failures, or a closed SSH session.
pub async fn start_local_forward(
    connection: HostConnection,
    listen: SocketAddr,
    destination: SocketAddr,
) -> Result<ForwardServer, SshClientError> {
    if let Err(error) = validate_forward_listen(listen, true) {
        return Err(close_after_forward_start_error(connection, error).await);
    }
    if destination.port() == 0 {
        return Err(close_after_forward_start_error(
            connection,
            SshClientError::Invalid("forward destination port must be nonzero".into()),
        )
        .await);
    }
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            return Err(close_after_forward_start_error(connection, error.into()).await);
        }
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            drop(listener);
            return Err(close_after_forward_start_error(connection, error.into()).await);
        }
    };
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(run_forward_listener(
        listener,
        connection,
        destination,
        stop_rx,
    ));
    Ok(ForwardServer {
        address,
        stop,
        task: Some(task),
    })
}

/// Validates a requested local forward bind address.
pub fn validate_forward_listen(
    address: SocketAddr,
    allow_ephemeral: bool,
) -> Result<(), SshClientError> {
    if !address.ip().is_loopback() {
        return Err(SshClientError::Invalid(
            "TCP forwarding may bind only to a loopback address".into(),
        ));
    }
    if address.port() == 0 && !allow_ephemeral {
        return Err(SshClientError::Invalid(
            "listen port must be nonzero".into(),
        ));
    }
    Ok(())
}

async fn close_after_forward_start_error(
    connection: HostConnection,
    error: SshClientError,
) -> SshClientError {
    match connection.close().await {
        Ok(()) => error,
        Err(cleanup) => SshClientError::Invalid(format!(
            "forward startup failed: {error}; SSH cleanup failed: {cleanup}"
        )),
    }
}

async fn run_forward_listener(
    listener: TcpListener,
    connection: HostConnection,
    destination: SocketAddr,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<(), SshClientError> {
    let connection = std::sync::Arc::new(connection);
    let slots = std::sync::Arc::new(Semaphore::new(MAX_LOCAL_FORWARD_CONNECTIONS));
    let mut workers = JoinSet::new();
    let mut accept_error = None;
    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (socket, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        accept_error = Some(SshClientError::Io(error));
                        break;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    eprintln!("hostlink: TCP forward connection limit ({MAX_LOCAL_FORWARD_CONNECTIONS}) reached");
                    continue;
                };
                workers.spawn(proxy_one(
                    socket,
                    connection.clone(),
                    destination,
                    stop_rx.clone(),
                    slot,
                ));
            }
            Some(joined) = workers.join_next(), if !workers.is_empty() => {
                if let Err(error) = joined {
                    eprintln!("hostlink: TCP forward worker failed: {error}");
                }
            }
        }
    }

    while let Some(joined) = workers.join_next().await {
        if let Err(error) = joined {
            eprintln!("hostlink: TCP forward worker failed during shutdown: {error}");
        }
    }
    let cleanup = match std::sync::Arc::try_unwrap(connection) {
        Ok(connection) => connection.close().await,
        Err(_) => Err(SshClientError::CleanupUnconfirmed),
    };
    match (accept_error, cleanup) {
        (None, result) => result,
        (Some(error), Ok(())) => Err(error),
        (Some(error), Err(cleanup)) => Err(SshClientError::Invalid(format!(
            "forward listener failed: {error}; SSH cleanup failed: {cleanup}"
        ))),
    }
}

async fn proxy_one(
    mut local: TcpStream,
    connection: std::sync::Arc<HostConnection>,
    destination: SocketAddr,
    mut stop_rx: watch::Receiver<bool>,
    _slot: tokio::sync::OwnedSemaphorePermit,
) {
    let open = tokio::time::timeout(FORWARD_OPEN_TIMEOUT, connection.open_forward(destination));
    let stream = tokio::select! {
        _ = stop_rx.changed() => return,
        result = open => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                eprintln!("hostlink: TCP forward to {destination} failed: {error}");
                return;
            }
            Err(_) => {
                eprintln!("hostlink: TCP forward to {destination} timed out opening SSH channel");
                return;
            }
        },
    };
    let mut remote = stream;
    tokio::select! {
        _ = stop_rx.changed() => {},
        result = tokio::io::copy_bidirectional(&mut local, &mut remote) => {
            if let Err(error) = result {
                eprintln!("hostlink: TCP forward stream to {destination} failed: {error}");
            }
        }
    }
}
