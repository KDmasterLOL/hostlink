//! Agent-owned TCP listener, bounded target-connect, and forwarding policy.

#[cfg(test)]
use crate::AgentConfig;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub(super) async fn connect_target(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> io::Result<TcpStream> {
    let timeout = Duration::from_millis(timeout_ms.clamp(1, 60_000));
    let addresses = tokio::net::lookup_host((host, port)).await?;
    connect_addresses(addresses, timeout).await
}

async fn connect_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out connecting to {address}"),
                ));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target host resolved to no socket addresses",
        )
    }))
}

pub(super) async fn bridge_tcp(mut left: TcpStream, mut right: TcpStream) -> io::Result<()> {
    tokio::io::copy_bidirectional(&mut left, &mut right)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpStream as StdTcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn bounded_connect_tries_later_resolved_addresses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let reachable = listener.local_addr().expect("listener address");
        let unreachable = SocketAddr::from(([127, 0, 0, 1], 0));

        let client = connect_addresses([unreachable, reachable], Duration::from_millis(250))
            .await
            .expect("later address should connect");
        let accepted = listener.accept().await.expect("accept").0;

        assert_eq!(client.peer_addr().expect("peer"), reachable);
        assert_eq!(
            accepted.peer_addr().expect("accepted peer"),
            client.local_addr().expect("client local")
        );
    }

    #[tokio::test]
    async fn empty_resolved_address_set_is_rejected() {
        let error = connect_addresses([], Duration::from_millis(10))
            .await
            .expect_err("empty resolution must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn bridge_preserves_left_to_right_half_close() {
        let (mut left_client, left_bridge) = connected_pair().await;
        let (right_bridge, mut right_server) = connected_pair().await;

        let worker = tokio::spawn(bridge_tcp(left_bridge, right_bridge));

        left_client.write_all(b"ping").await.expect("left write");
        left_client.shutdown().await.expect("left eof");

        let mut request = Vec::new();
        right_server
            .read_to_end(&mut request)
            .await
            .expect("right request");
        assert_eq!(request, b"ping");

        right_server.write_all(b"pong").await.expect("right write");
        right_server.shutdown().await.expect("right eof");

        let mut response = Vec::new();
        left_client
            .read_to_end(&mut response)
            .await
            .expect("left response");
        assert_eq!(response, b"pong");

        worker.await.expect("bridge worker").expect("bridge");
    }

    #[tokio::test]
    async fn bridge_surfaces_forwarding_io_failure() {
        let (left_client, left_bridge) = connected_std_pair();
        let (right_bridge, mut right_server) = connected_std_pair();

        left_bridge
            .shutdown(Shutdown::Both)
            .expect("disable bridge endpoint");
        std::io::Write::write_all(&mut right_server, b"payload").expect("right write");
        right_server.shutdown(Shutdown::Write).expect("right eof");

        left_bridge.set_nonblocking(true).expect("left nonblocking");
        right_bridge
            .set_nonblocking(true)
            .expect("right nonblocking");
        let error = bridge_tcp(
            TcpStream::from_std(left_bridge).expect("left async"),
            TcpStream::from_std(right_bridge).expect("right async"),
        )
        .await
        .expect_err("write into a shut down endpoint must remain visible");
        assert_ne!(error.kind(), io::ErrorKind::WouldBlock);

        drop(left_client);
    }

    #[tokio::test]
    async fn bridge_preserves_right_to_left_half_close() {
        let (mut left_client, left_bridge) = connected_pair().await;
        let (right_bridge, mut right_server) = connected_pair().await;

        let worker = tokio::spawn(bridge_tcp(left_bridge, right_bridge));

        right_server
            .write_all(b"request")
            .await
            .expect("right write");
        right_server.shutdown().await.expect("right eof");

        let mut request = Vec::new();
        left_client
            .read_to_end(&mut request)
            .await
            .expect("left request");
        assert_eq!(request, b"request");

        left_client
            .write_all(b"response")
            .await
            .expect("left write");
        left_client.shutdown().await.expect("left eof");

        let mut response = Vec::new();
        right_server
            .read_to_end(&mut response)
            .await
            .expect("right response");
        assert_eq!(response, b"response");

        worker.await.expect("bridge worker").expect("bridge");
    }

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("connect");
        let server = listener.accept().await.expect("accept").0;
        (client, server)
    }

    fn connected_std_pair() -> (StdTcpStream, StdTcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let client = StdTcpStream::connect(address).expect("connect");
        let server = listener.accept().expect("accept").0;
        (client, server)
    }

    #[test]
    fn production_forwarding_has_no_blocking_thread_or_connect_timeout() {
        let source = include_str!("network.rs")
            .split("mod tests {")
            .next()
            .expect("production source");
        assert!(!source.contains("std::thread"));
        assert!(!source.contains("thread::spawn"));
        assert!(!source.contains("connect_timeout"));
        assert!(source.contains("tokio::io::copy_bidirectional"));
    }

    #[test]
    fn literal_ipv4_and_ipv6_loopback_listeners_validate() {
        for listen in ["127.0.0.1:27391", "[::1]:27391"] {
            let config: AgentConfig = serde_json::from_value(serde_json::json!({
                "version": 1,
                "name": "agent",
                "listen": listen,
            }))
            .expect("literal socket listener config");

            assert_eq!(config.listen(), listen.parse().expect("socket"));
            config.validate().expect("loopback listener config");
            let serialized = serde_json::to_value(&config).expect("serialize config");
            assert_eq!(serialized["listen"], listen);
        }
    }

    #[test]
    fn invalid_listener_syntax_is_rejected_during_deserialization() {
        let error = serde_json::from_str::<AgentConfig>(
            r#"{
                "version": 1,
                "name": "agent",
                "listen": "localhost:27391"
            }"#,
        )
        .expect_err("hostname listener must not deserialize as SocketAddr");

        assert!(error.to_string().contains("socket address"));
    }
}
