//! SSH direct-tcpip forwarding over an authenticated target connection.

use std::net::SocketAddr;

use crate::connect::{HostConnection, OPERATION_TIMEOUT, SshClientError};

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
