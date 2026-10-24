//! Loopback-only TCP forwarding through managed SSH or gateway-control agent routing.

use super::model::{RemoteAgentClient, RemoteCarrier, RemoteTcpStream};
use super::protocol::{read_response_unbuffered, response_into_kind, write_request};
use super::ssh::RemoteChannel;
use crate::AppResult;
#[cfg(test)]
use anyhow::Context;
use onec_agent_protocol::{AgentRequest, AgentRequestKind, AgentResponseKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

const MAX_FORWARD_CONNECTIONS: usize = 32;

impl RemoteAgentClient {
    /// Serves a bounded-concurrency loopback TCP forward to one target host/port.
    ///
    /// At most 32 relay workers are active concurrently; excess accepted sockets fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the listen address is non-loopback, bind/accept/task
    /// setup fails, or forwarding infrastructure cannot be established.
    pub async fn forward(
        &self,
        listen: SocketAddr,
        target_host: String,
        target_port: u16,
    ) -> AppResult<()> {
        if !listen.ip().is_loopback() {
            return Err(crate::invalid_config(format!(
                "remote forwards must listen on loopback only, got {listen}"
            )));
        }

        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|source| crate::io_error(PathBuf::from(format!("tcp://{listen}")), source))?;
        let permits = Arc::new(Semaphore::new(MAX_FORWARD_CONNECTIONS));
        let mut relays = JoinSet::new();
        loop {
            tokio::select! {
                completed = relays.join_next(), if !relays.is_empty() => {
                    if let Some(Err(error)) = completed
                        && !error.is_cancelled()
                    {
                        eprintln!("onec-access forward task failed: {error}");
                    }
                }
                accepted = listener.accept() => {
                    let (local, _) = accepted.map_err(|source| {
                        crate::io_error(PathBuf::from(format!("tcp://{listen}")), source)
                    })?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        drop(local);
                        continue;
                    };
                    let client = self.clone();
                    let host = target_host.clone();
                    spawn_forward_worker(&mut relays, permit, async move {
                        client.forward_one(local, &host, target_port).await
                    });
                }
            }
        }
    }

    /// Opens one bidirectional remote TCP stream through the selected carrier.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for invalid host/port/timeout or carrier/control-channel failure.
    pub async fn tcp_connect_stream(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> AppResult<RemoteTcpStream> {
        let channel = self.tcp_connect_channel(host, port, timeout).await?;
        Ok(RemoteTcpStream { channel })
    }

    async fn tcp_connect_channel(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> AppResult<RemoteChannel> {
        validate_tcp_target(host, port, timeout)?;
        if self.server.carrier == RemoteCarrier::TargetSsh {
            return self.open_target_tcp_channel(host, port, timeout).await;
        }

        let timeout_ms = timeout.as_millis().try_into().unwrap_or(u64::MAX);
        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::TcpConnect {
                host: host.to_owned(),
                port,
                timeout_ms,
            },
        );
        let mut agent = self.open_channel().await?;
        write_request(&mut agent, &request)
            .await
            .map_err(|source| {
                crate::invalid_config(format!("failed to send TCP connect request: {source}"))
            })?;
        let response = read_response_unbuffered(&mut agent).await?;
        match response_into_kind(response)? {
            AgentResponseKind::TcpReady => Ok(agent),
            other => Err(crate::invalid_config(format!(
                "agent returned unexpected TCP response: {other:?}"
            ))),
        }
    }

    #[cfg(test)]
    pub(in crate::remote) async fn tcp_connect_stream_via(
        &self,
        control: SocketAddr,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> AppResult<tokio::net::TcpStream> {
        validate_tcp_target(host, port, timeout)?;
        let timeout_ms = timeout.as_millis().try_into().unwrap_or(u64::MAX);
        let secret = self.server.secret()?;
        let request = AgentRequest::new(
            secret,
            AgentRequestKind::TcpConnect {
                host: host.to_owned(),
                port,
                timeout_ms,
            },
        );
        let mut agent = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(control),
        )
        .await
        .map_err(|_| {
            crate::invalid_config(format!(
                "connecting to TCP test control endpoint {control} timed out"
            ))
        })?
        .map_err(|source| crate::io_error(PathBuf::from(format!("tcp://{control}")), source))?;
        write_request(&mut agent, &request)
            .await
            .map_err(|source| {
                crate::invalid_config(format!("failed to send TCP connect request: {source}"))
            })?;
        let response = read_response_unbuffered(&mut agent).await?;
        match response_into_kind(response)? {
            AgentResponseKind::TcpReady => Ok(agent),
            other => Err(crate::invalid_config(format!(
                "agent returned unexpected TCP response: {other:?}"
            ))),
        }
    }

    pub(in crate::remote) async fn forward_one(
        &self,
        local: tokio::net::TcpStream,
        host: &str,
        port: u16,
    ) -> AppResult<()> {
        self.tcp_connect_channel(host, port, Duration::from_secs(5))
            .await?
            .bridge_tcp(local)
            .await
    }
}

fn spawn_forward_worker<F>(relays: &mut JoinSet<()>, permit: OwnedSemaphorePermit, future: F)
where
    F: std::future::Future<Output = AppResult<()>> + Send + 'static,
{
    relays.spawn(async move {
        let result = with_forward_permit(permit, future).await;
        if let Err(error) = result {
            eprintln!("onec-access forward: {error}");
        }
    });
}

async fn with_forward_permit<F>(permit: OwnedSemaphorePermit, future: F) -> F::Output
where
    F: std::future::Future,
{
    let _permit = permit;
    future.await
}

#[cfg(test)]
async fn relay_tcp<L, R>(local: &mut L, remote: &mut R) -> AppResult<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(local, remote)
        .await
        .context("bridging local TCP stream over embedded SSH channel")?;
    Ok(())
}

fn validate_tcp_target(host: &str, port: u16, timeout: Duration) -> AppResult<()> {
    if host.trim().is_empty() || port == 0 || timeout.is_zero() {
        return Err(crate::invalid_config(
            "remote TCP connect requires a non-empty host, non-zero port, and positive timeout"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let client = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .expect("loopback connect bounded")
        .expect("loopback connect");
        let (server, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("loopback accept bounded")
            .expect("loopback accept");
        (client, server)
    }

    async fn relay_pair() -> (
        tokio::net::TcpStream,
        tokio::net::TcpStream,
        tokio::task::JoinHandle<AppResult<()>>,
    ) {
        let (local_peer, mut local_relay) = tcp_pair().await;
        let (remote_peer, mut remote_relay) = tcp_pair().await;
        let relay =
            tokio::spawn(async move { relay_tcp(&mut local_relay, &mut remote_relay).await });
        (local_peer, remote_peer, relay)
    }

    #[test]
    fn forward_connection_permits_are_bounded_and_released() {
        let permits = Arc::new(Semaphore::new(MAX_FORWARD_CONNECTIONS));
        let held = (0..MAX_FORWARD_CONNECTIONS)
            .map(|_| {
                Arc::clone(&permits)
                    .try_acquire_owned()
                    .expect("forward slot")
            })
            .collect::<Vec<_>>();
        assert!(
            Arc::clone(&permits).try_acquire_owned().is_err(),
            "forward limit must fail closed"
        );
        drop(held);
        assert!(
            Arc::clone(&permits).try_acquire_owned().is_ok(),
            "dropping a forward worker releases its slot"
        );
    }

    #[tokio::test]
    async fn loopback_relay_forwards_bytes_in_both_directions() {
        let (mut local, mut remote, relay) = relay_pair().await;
        local.write_all(b"from-local").await.expect("local write");
        remote
            .write_all(b"from-remote")
            .await
            .expect("remote write");

        let mut local_received = [0; 11];
        let mut remote_received = [0; 10];
        tokio::time::timeout(Duration::from_secs(2), async {
            local
                .read_exact(&mut local_received)
                .await
                .expect("local receives remote bytes");
            remote
                .read_exact(&mut remote_received)
                .await
                .expect("remote receives local bytes");
        })
        .await
        .expect("bidirectional transfer bounded");
        assert_eq!(&local_received, b"from-remote");
        assert_eq!(&remote_received, b"from-local");

        local.shutdown().await.expect("local half-close");
        remote.shutdown().await.expect("remote half-close");
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay closes after both EOFs")
            .expect("relay task")
            .expect("relay result");
    }

    #[tokio::test]
    async fn loopback_relay_propagates_half_close_and_preserves_reply() {
        let (mut local, mut remote, relay) = relay_pair().await;
        local.write_all(b"request").await.expect("request write");
        local.shutdown().await.expect("local write half-close");

        let mut request = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), remote.read_to_end(&mut request))
            .await
            .expect("remote observes EOF")
            .expect("remote read");
        assert_eq!(request, b"request");

        remote
            .write_all(b"reply-after-eof")
            .await
            .expect("reply write");
        remote.shutdown().await.expect("remote write half-close");
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), local.read_to_end(&mut reply))
            .await
            .expect("local observes remote EOF")
            .expect("local read");
        assert_eq!(reply, b"reply-after-eof");
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay completes")
            .expect("relay task")
            .expect("relay result");
    }

    #[tokio::test]
    async fn loopback_peer_disconnect_propagates_eof_and_ends_relay() {
        let (mut local, mut remote, relay) = relay_pair().await;
        local.write_all(b"before-disconnect").await.expect("write");
        drop(local);

        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), remote.read_to_end(&mut remaining))
            .await
            .expect("remote observes disconnected peer EOF")
            .expect("remote read");
        assert_eq!(remaining, b"before-disconnect");
        drop(remote);
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay ends after peer disconnect")
            .expect("relay task")
            .expect("relay result");
    }

    #[tokio::test]
    async fn dropping_forward_owner_cancels_relays_and_releases_connection_slot() {
        let permits = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&permits)
            .try_acquire_owned()
            .expect("forward slot");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut relays = JoinSet::new();
        spawn_forward_worker(&mut relays, permit, async move {
            let _ = started_tx.send(());
            std::future::pending::<AppResult<()>>().await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("relay worker starts")
            .expect("worker start signal");
        assert_eq!(permits.available_permits(), 0);

        drop(relays);
        let permit = tokio::time::timeout(Duration::from_secs(2), permits.acquire())
            .await
            .expect("dropping forward owner cancels relay worker")
            .expect("forward slot returns after owner cancellation");
        drop(permit);
        assert_eq!(permits.available_permits(), 1);
    }
}
