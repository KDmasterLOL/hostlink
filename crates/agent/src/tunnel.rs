//! Optional pinned reverse SSH connection to an approved gateway.
use crate::{AgentConfig, ReverseGateway};
use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

const MAX_FORWARDS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(60);

struct AttemptFailure {
    error: io::Error,
    transient: bool,
}

impl AttemptFailure {
    fn permanent(error: io::Error) -> Self {
        Self {
            error,
            transient: false,
        }
    }

    fn transient(error: io::Error) -> Self {
        Self {
            error,
            transient: true,
        }
    }
}

fn ssh_failure(error: russh::Error) -> AttemptFailure {
    match error {
        russh::Error::UnknownKey => AttemptFailure::permanent(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway host key does not match the configured pin",
        )),
        russh::Error::IO(error) if is_transient_io(&error) => AttemptFailure::transient(error),
        russh::Error::HUP
        | russh::Error::Disconnect
        | russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::RecvError
        | russh::Error::SendError => AttemptFailure::transient(io::Error::other(error)),
        error => AttemptFailure::permanent(io::Error::other(error)),
    }
}

fn is_transient_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::WouldBlock
    )
}

struct GatewayHandler {
    host_key: russh::keys::PublicKey,
    remote_port: u16,
    forwards: mpsc::Sender<(Channel<Msg>, ChannelOpenHandle)>,
}

impl client::Handler for GatewayHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(presented.certificate().is_none()
            && presented.public_key().algorithm() == Algorithm::Ed25519
            && presented.public_key().key_data() == self.host_key.key_data())
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        address: &str,
        port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if address != "127.0.0.1" || port != u32::from(self.remote_port) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        } else if let Err(error) = self.forwards.try_send((channel, reply)) {
            let (_, reply) = error.into_inner();
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
        }
        Ok(())
    }
}

/// Runs the optional pinned reverse tunnel until shutdown, reconnecting transient failures.
pub async fn run(
    config: &AgentConfig,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    run_with_backoff(
        config,
        shutdown,
        INITIAL_RECONNECT_BACKOFF,
        MAX_RECONNECT_BACKOFF,
    )
    .await
}

async fn run_with_backoff(
    config: &AgentConfig,
    shutdown: impl Future<Output = ()> + Send,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> io::Result<()> {
    config.validate()?;
    let Some(gateway) = config.gateway.as_ref() else {
        return Ok(());
    };
    let host_key = load_gateway_key(&gateway.host_public_key)?;
    let identity = load_identity(&gateway.identity)?;
    tokio::pin!(shutdown);
    let mut backoff = initial_backoff.min(max_backoff);
    loop {
        let attempt = tunnel_once(gateway, &host_key, identity.clone(), config.listen);
        let result = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            result = attempt => result,
        };
        match result {
            Ok(()) => return Ok(()),
            Err(failure) if !failure.transient => return Err(failure.error),
            Err(_) => {}
        }
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(max_backoff);
    }
}

async fn tunnel_once(
    gateway: &ReverseGateway,
    host_key: &russh::keys::PublicKey,
    identity: PrivateKey,
    target: std::net::SocketAddr,
) -> Result<(), AttemptFailure> {
    let (tx, mut rx) = mpsc::channel(MAX_FORWARDS);
    let handler = GatewayHandler {
        host_key: host_key.clone(),
        remote_port: gateway.remote_port,
        forwards: tx,
    };
    let ssh_config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });
    let mut session = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(ssh_config, (gateway.host.as_str(), gateway.port), handler),
    )
    .await
    .map_err(|_| {
        AttemptFailure::transient(io::Error::new(
            io::ErrorKind::TimedOut,
            "gateway SSH connect timed out",
        ))
    })?
    .map_err(ssh_failure)?;
    let auth = tokio::time::timeout(
        CONNECT_TIMEOUT,
        session.authenticate_publickey(
            gateway.user.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(identity), None),
        ),
    )
    .await
    .map_err(|_| {
        AttemptFailure::transient(io::Error::new(
            io::ErrorKind::TimedOut,
            "gateway SSH authentication timed out",
        ))
    })?
    .map_err(ssh_failure)?;
    if !auth.success() {
        return Err(AttemptFailure::permanent(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway rejected pinned SSH identity",
        )));
    }
    let forwarded = tokio::time::timeout(
        CONNECT_TIMEOUT,
        session.tcpip_forward("127.0.0.1", u32::from(gateway.remote_port)),
    )
    .await
    .map_err(|_| {
        AttemptFailure::transient(io::Error::new(
            io::ErrorKind::TimedOut,
            "reverse forward request timed out",
        ))
    })?
    .map_err(ssh_failure)?;
    if forwarded != u32::from(gateway.remote_port) {
        return Err(AttemptFailure::permanent(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway did not confirm the exact requested reverse loopback port",
        )));
    }
    let slots = Arc::new(Semaphore::new(MAX_FORWARDS));
    let mut workers = tokio::task::JoinSet::new();
    let connection = async {
        loop {
            tokio::select! {
                result = &mut session => return result.map_err(ssh_failure),
                request = rx.recv() => {
                    let Some((channel, reply)) = request else { return Err(AttemptFailure::transient(io::Error::new(io::ErrorKind::UnexpectedEof, "gateway forward queue closed"))) };
                    let Ok(permit) = slots.clone().try_acquire_owned() else { reply.reject(ChannelOpenFailure::ResourceShortage).await; continue };
                    workers.spawn(async move {
                        let _permit = permit;
                        let target = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(target)).await;
                        let Ok(Ok(mut socket)) = target else { reply.reject(ChannelOpenFailure::ConnectFailed).await; return };
                        reply.accept().await;
                        let mut ssh = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut ssh, &mut socket).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut ssh).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
                    });
                }
                Some(_) = workers.join_next(), if !workers.is_empty() => {}
            }
        }
    };
    let result = connection.await;
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    result
}

fn load_gateway_key(path: &Path) -> io::Result<russh::keys::PublicKey> {
    crate::ssh::validate_private_path(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway pin must be a bounded regular file",
        ));
    }
    let text = std::fs::read_to_string(path)?;
    let key = russh::keys::PublicKey::from_openssh(text.trim()).map_err(io::Error::other)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway pin must be Ed25519",
        ));
    }
    Ok(key)
}
fn load_identity(path: &Path) -> io::Result<PrivateKey> {
    crate::ssh::validate_private_path(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway identity must be a bounded regular file",
        ));
    }
    let key = PrivateKey::from_openssh(&std::fs::read(path)?).map_err(io::Error::other)?;
    if key.is_encrypted() || key.algorithm() != Algorithm::Ed25519 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway identity must be unencrypted Ed25519",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::LineEnding;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(windows)]
    fn protect_test_fixture(path: &Path, directory: bool) {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
        use windows_permissions::{LocalBox, SecurityDescriptor};

        let owner = windows_permissions::utilities::current_process_sid()
            .expect("read the current Windows fixture owner");
        let sid = ConvertSidToStringSid(&owner).expect("encode fixture owner SID");
        let inheritance = if directory { "OICI" } else { "" };
        let dacl: LocalBox<SecurityDescriptor> =
            format!("D:P(A;{inheritance};FA;;;{})", sid.to_string_lossy())
                .parse()
                .expect("construct current-user private DACL");
        SetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner
                | SecurityInformation::Dacl
                | SecurityInformation::ProtectedDacl,
            Some(owner.as_ref()),
            None,
            dacl.dacl(),
            None,
        )
        .expect("set the verified private fixture owner and protected DACL");
    }

    #[tokio::test]
    async fn transient_gateway_loss_retries_until_shutdown() {
        let temp = tempfile::tempdir().expect("private test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private test directory permissions");
        }
        #[cfg(windows)]
        protect_test_fixture(temp.path(), true);

        let identity =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller identity");
        let pin = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("gateway pin");
        let identity_path = temp.path().join("identity");
        let pin_path = temp.path().join("gateway.pub");
        std::fs::write(
            &identity_path,
            identity
                .to_openssh(LineEnding::LF)
                .expect("encode controller identity")
                .as_bytes(),
        )
        .expect("write controller identity");
        std::fs::write(
            &pin_path,
            pin.public_key().to_openssh().expect("encode gateway pin"),
        )
        .expect("write gateway pin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))
                .expect("private identity permissions");
            std::fs::set_permissions(&pin_path, std::fs::Permissions::from_mode(0o600))
                .expect("private pin permissions");
        }
        #[cfg(windows)]
        {
            protect_test_fixture(&identity_path, false);
            protect_test_fixture(&pin_path, false);
        }

        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind simulated gateway");
        let gateway_addr = gateway_listener.local_addr().expect("gateway address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_by_server = accepted.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let gateway = tokio::spawn(async move {
            let mut shutdown_tx = Some(shutdown_tx);
            loop {
                let (socket, _) = gateway_listener.accept().await.expect("accept gateway TCP");
                drop(socket); // The gateway is unreachable at SSH protocol level.
                if accepted_by_server.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                    let _ = shutdown_tx.take().expect("single shutdown").send(());
                }
            }
        });

        let config = AgentConfig {
            listen: "127.0.0.1:43210".parse().expect("loopback target"),
            user: "agent".into(),
            host_key: temp.path().join("unused-host-key"),
            authorized_keys: temp.path().join("unused-authorized-keys"),
            jobs_root: temp.path().join("unused-jobs"),
            gateway: Some(ReverseGateway {
                host: gateway_addr.ip().to_string(),
                port: gateway_addr.port(),
                user: "gateway-user".into(),
                identity: identity_path,
                host_public_key: pin_path,
                remote_port: 40222,
            }),
        };

        let result = tokio::time::timeout(
            Duration::from_secs(3),
            run_with_backoff(
                &config,
                async move {
                    let _ = shutdown_rx.await;
                },
                Duration::from_millis(5),
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("tunnel should wait for explicit shutdown");
        assert!(result.is_ok(), "shutdown result: {result:?}");
        assert!(
            accepted.load(Ordering::SeqCst) >= 3,
            "multiple attempts occurred"
        );
        gateway.abort();
    }

    #[test]
    fn host_key_mismatch_is_classified_as_permanent() {
        let failure = ssh_failure(russh::Error::UnknownKey);
        assert!(!failure.transient);
        assert_eq!(failure.error.kind(), io::ErrorKind::PermissionDenied);
    }
}
