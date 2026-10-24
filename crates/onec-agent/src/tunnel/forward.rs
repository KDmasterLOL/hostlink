//! Forwarded SSH channels from the gateway to the local target service.

use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::keys::{Algorithm, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;

pub(super) const MAX_FORWARD_CHANNELS: usize = 32;
const LOCAL_FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct ForwardRequest {
    pub(super) channel: Channel<Msg>,
    pub(super) reply: ChannelOpenHandle,
}

pub(super) struct GatewayHandler {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) known_hosts: PathBuf,
    pub(super) remote_port: u16,
    pub(super) forwards: mpsc::Sender<ForwardRequest>,
}

impl client::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if server_public_key.certificate().is_some()
            || server_public_key.public_key().algorithm() != Algorithm::Ed25519
        {
            return Ok(false);
        }
        Ok(russh::keys::check_known_hosts_path(
            &self.host,
            self.port,
            &server_public_key.public_key(),
            &self.known_hosts,
        )?)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if connected_address != "127.0.0.1" || connected_port != u32::from(self.remote_port) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        let request = ForwardRequest { channel, reply };
        match self.forwards.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(request))
            | Err(mpsc::error::TrySendError::Closed(request)) => {
                request
                    .reply
                    .reject(ChannelOpenFailure::ResourceShortage)
                    .await;
            }
        }
        Ok(())
    }
}

pub(super) async fn run_bridge_manager(
    mut requests: mpsc::Receiver<ForwardRequest>,
    local_target_port: u16,
    shutdown: oneshot::Receiver<()>,
) {
    let slots = Arc::new(Semaphore::new(MAX_FORWARD_CHANNELS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            request = requests.recv() => {
                let Some(request) = request else {
                    break;
                };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    request.reply.reject(ChannelOpenFailure::ResourceShortage).await;
                    continue;
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_forward(request, local_target_port).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    while let Ok(request) = requests.try_recv() {
        request
            .reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn handle_forward(request: ForwardRequest, local_target_port: u16) {
    let target = tokio::time::timeout(
        LOCAL_FORWARD_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(("127.0.0.1", local_target_port)),
    )
    .await;
    let Ok(Ok(mut target)) = target else {
        request
            .reply
            .reject(ChannelOpenFailure::ConnectFailed)
            .await;
        return;
    };

    request.reply.accept().await;
    let mut channel = request.channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut channel, &mut target).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut channel).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut target).await;
}
