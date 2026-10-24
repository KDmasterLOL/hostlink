use super::{
    EmbeddedSshConfig, load_private_ed25519_key, load_public_ed25519_key, serve_prepared_until,
};
use crate::EmbeddedSshServerConfig;
use russh::ChannelMsg;
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(15);

struct StrictHostKey {
    expected: PublicKey,
}

impl client::Handler for StrictHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(server_public_key.certificate().is_none()
            && server_public_key.public_key().algorithm() == self.expected.algorithm()
            && server_public_key.public_key().key_data() == self.expected.key_data())
    }
}

/// Proves one exact embedded target-SSH candidate with real authentication, SFTP and forwarding.
///
/// The caller supplies a scratch directory and a controller identity whose public key is already
/// present in the configured authorized-keys file. The probe binds only the configured loopback
/// port, creates and removes one scratch file through SFTP, exercises direct-tcpip against an
/// ephemeral loopback echo socket, then shuts the server down through the production lifecycle.
///
/// # Errors
///
/// Returns an I/O error when candidate configuration/key material is invalid, authentication fails,
/// SFTP or forwarding does not round-trip exact bytes, or startup/shutdown exceeds its deadline.
pub async fn preflight_embedded_ssh(
    config: &EmbeddedSshServerConfig,
    advertised_host_public_key: &Path,
    controller_identity: &Path,
    scratch_dir: &Path,
) -> io::Result<()> {
    if !scratch_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "embedded SSH preflight scratch directory does not exist: {}",
                scratch_dir.display()
            ),
        ));
    }

    let embedded = EmbeddedSshConfig::new(
        config.user.clone(),
        config.host_key.clone(),
        config.authorized_keys.clone(),
    );
    let prepared = embedded.prepare()?;
    let expected_host_key = load_public_ed25519_key(
        advertised_host_public_key,
        "advertised embedded SSH host key",
    )?;
    if prepared.host_key.public_key().algorithm() != expected_host_key.algorithm()
        || prepared.host_key.public_key().key_data() != expected_host_key.key_data()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "advertised embedded SSH host public key does not match the configured private key",
        ));
    }
    let controller_identity = Arc::new(load_private_ed25519_key(
        controller_identity,
        "embedded SSH preflight controller identity",
    )?);

    // Candidate preparation runs before the existing managed transport is stopped. Bind an
    // ephemeral loopback port here so migration from an installed external sshd can be proven
    // without colliding with its final target port. The emitted runtime config retains the
    // configured port and normal startup/rollback proves that bind during cutover.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_prepared_until(listener, prepared, async move {
        let _ = shutdown_rx.await;
    }));

    let probe = tokio::time::timeout(
        PREFLIGHT_TIMEOUT,
        run_client_probe(
            address,
            &config.user,
            expected_host_key,
            controller_identity,
            scratch_dir,
        ),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "embedded SSH candidate preflight timed out",
        )
    })
    .and_then(|result| result);

    let _ = shutdown_tx.send(());
    let server_result = tokio::time::timeout(PREFLIGHT_TIMEOUT, server)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "embedded SSH candidate server shutdown timed out",
            )
        })
        .and_then(|result| result.map_err(io::Error::other))
        .and_then(|result| result);

    match (probe, server_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_client_probe(
    address: std::net::SocketAddr,
    user: &str,
    expected_host_key: PublicKey,
    controller_identity: Arc<russh::keys::PrivateKey>,
    scratch_dir: &Path,
) -> io::Result<()> {
    let mut session = client::connect(
        Arc::new(client::Config::default()),
        address,
        StrictHostKey {
            expected: expected_host_key,
        },
    )
    .await
    .map_err(io::Error::other)?;

    let auth = session
        .authenticate_publickey(
            user.to_owned(),
            PrivateKeyWithHashAlg::new(controller_identity, None),
        )
        .await
        .map_err(io::Error::other)?;
    if !auth.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "embedded SSH candidate rejected controller public-key authentication",
        ));
    }

    let sftp = open_sftp(&session).await?;
    let scratch = scratch_dir.join(format!(
        "onec embedded ssh проверка {}-{}.bin",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    ));
    let scratch_text = scratch.to_string_lossy().into_owned();
    let payload = b"onec-embedded-ssh-preflight";

    let sftp_result = async {
        if sftp
            .try_exists(scratch_text.clone())
            .await
            .map_err(io::Error::other)?
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "embedded SSH preflight scratch path already exists: {}",
                    scratch.display()
                ),
            ));
        }

        let mut remote = sftp
            .open_with_flags(
                scratch_text.clone(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .map_err(io::Error::other)?;
        remote.write_all(payload).await?;
        remote.close().await?;

        let mut remote = sftp
            .open(scratch_text.clone())
            .await
            .map_err(io::Error::other)?;
        let mut restored = Vec::new();
        remote.read_to_end(&mut restored).await?;
        remote.close().await?;
        if restored != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "embedded SSH preflight SFTP round-trip changed bytes",
            ));
        }

        sftp.remove_file(scratch_text.clone())
            .await
            .map_err(io::Error::other)?;
        if sftp
            .try_exists(scratch_text.clone())
            .await
            .map_err(io::Error::other)?
        {
            return Err(io::Error::other(
                "embedded SSH preflight SFTP cleanup did not remove scratch file",
            ));
        }
        Ok(())
    }
    .await;

    if sftp_result.is_err() {
        let _ = sftp.remove_file(scratch_text).await;
    }
    sftp_result?;
    sftp.close().await.map_err(io::Error::other)?;

    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_listener.local_addr()?.port();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        if request != b"ping" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "embedded SSH preflight forwarding changed request bytes",
            ));
        }
        stream.write_all(b"pong").await?;
        stream.shutdown().await
    });

    let channel = session
        .channel_open_direct_tcpip("127.0.0.1", echo_port.into(), "127.0.0.1", 0)
        .await
        .map_err(io::Error::other)?;
    let mut forwarded = channel.into_stream();
    forwarded.write_all(b"ping").await?;
    forwarded.shutdown().await?;
    let mut response = Vec::new();
    forwarded.read_to_end(&mut response).await?;
    if response != b"pong" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "embedded SSH preflight forwarding changed response bytes",
        ));
    }
    echo.await.map_err(io::Error::other)??;

    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "embedded SSH preflight complete",
            "en",
        )
        .await
        .map_err(io::Error::other)
}

async fn open_sftp(session: &russh::client::Handle<StrictHostKey>) -> io::Result<SftpSession> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(io::Error::other)?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(io::Error::other)?;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "embedded SSH candidate rejected SFTP subsystem",
                ));
            }
            Some(_) => {}
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "embedded SSH candidate closed SFTP channel before acknowledgement",
                ));
            }
        }
    }

    SftpSession::new(channel.into_stream())
        .await
        .map_err(io::Error::other)
}
