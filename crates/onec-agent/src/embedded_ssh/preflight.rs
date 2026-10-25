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
#[cfg(any(windows, test))]
const EXEC_PROBE_COMMAND: &str = "$i=[Console]::OpenStandardInput();$o=[Console]::OpenStandardOutput();$b=New-Object byte[] 1024;while(($n=$i.Read($b,0,$b.Length))-gt 0){$o.Write($b,0,$n)};$o.Flush();$e=[Console]::OpenStandardError();$x=[byte[]](104,111,115,116,108,105,110,107,45,101,120,101,99,45,112,114,111,98,101);$e.Write($x,0,$x.Length);$e.Flush();exit 7";
#[cfg(any(windows, test))]
const EXEC_PROBE_INPUT: &[u8] = b"HostLink embedded SSH exec probe\0\x01\x7f\xff";
#[cfg(any(windows, test))]
const EXEC_PROBE_STDERR: &[u8] = b"hostlink-exec-probe";
#[cfg(windows)]
const EXEC_PROBE_OUTPUT_LIMIT: usize = 1024;
#[cfg(windows)]
const EXEC_PROBE_STDERR_LIMIT: usize = 128;

#[cfg(any(windows, test))]
fn exec_probe_mismatch(
    stdout: &[u8],
    stderr: &[u8],
    exit_status: Option<u32>,
    eof: bool,
    close: bool,
) -> Option<String> {
    let stdout_matches = stdout == EXEC_PROBE_INPUT;
    let stderr_matches = stderr == EXEC_PROBE_STDERR;
    let status_matches = exit_status == Some(7);
    (!(stdout_matches && stderr_matches && status_matches && eof && close)).then(|| {
        format!(
            "embedded SSH exec probe mismatch: stdout_match={stdout_matches} stdout_len={} stderr_match={stderr_matches} stderr_len={} exit_status={exit_status:?} eof={eof} close={close}",
            stdout.len(),
            stderr.len(),
        )
    })
}

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
    preflight_embedded_ssh_with_exec(
        config,
        advertised_host_public_key,
        controller_identity,
        scratch_dir,
        false,
    )
    .await
}

/// As [`preflight_embedded_ssh`], optionally validating the fixed Windows exec probe.
pub async fn preflight_embedded_ssh_with_exec(
    config: &EmbeddedSshServerConfig,
    advertised_host_public_key: &Path,
    controller_identity: &Path,
    scratch_dir: &Path,
    check_exec: bool,
) -> io::Result<()> {
    if check_exec {
        #[cfg(windows)]
        if !super::exec::safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "embedded SSH exec preflight requires a verified non-elevated, non-LocalSystem Windows user context",
            ));
        }
        #[cfg(not(windows))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "embedded SSH exec preflight is available only on Windows",
        ));
    }
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
            check_exec,
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
    check_exec: bool,
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

    if check_exec {
        #[cfg(windows)]
        run_exec_probe(&mut session).await?;
    }

    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "embedded SSH preflight complete",
            "en",
        )
        .await
        .map_err(io::Error::other)
}

#[cfg(windows)]
async fn run_exec_probe(session: &mut client::Handle<StrictHostKey>) -> io::Result<()> {
    use russh::ChannelMsg;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(io::Error::other)?;
    channel
        .exec(true, EXEC_PROBE_COMMAND)
        .await
        .map_err(io::Error::other)?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "embedded SSH exec probe request was rejected",
                ));
            }
            Some(_) => {}
            None => {
                return Err(io::Error::other(
                    "embedded SSH exec channel closed before acknowledgement",
                ));
            }
        }
    }

    channel
        .data_bytes(EXEC_PROBE_INPUT)
        .await
        .map_err(io::Error::other)?;
    channel.eof().await.map_err(io::Error::other)?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut exit_status, mut eof, mut close) = (None, false, false);
    while !close {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if stdout.len().saturating_add(data.len()) > EXEC_PROBE_OUTPUT_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "embedded SSH exec probe stdout exceeded its limit",
                    ));
                }
                stdout.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                if stderr.len().saturating_add(data.len()) > EXEC_PROBE_STDERR_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "embedded SSH exec probe stderr exceeded its limit",
                    ));
                }
                stderr.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExtendedData { .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "embedded SSH exec probe returned unsupported extended data",
                ));
            }
            Some(ChannelMsg::ExitStatus {
                exit_status: status,
            }) => exit_status = Some(status),
            Some(ChannelMsg::Eof) => eof = true,
            Some(ChannelMsg::Close) => close = true,
            Some(_) => {}
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    exec_probe_mismatch(&stdout, &stderr, exit_status, eof, close)
                        .expect("channel ended before close is an exec probe mismatch"),
                ));
            }
        }
    }
    // russh 0.63 responds to the peer's CHANNEL_CLOSE while processing it, then removes
    // the channel. Sending a second close here can fail with ChannelClosed.
    if let Some(mismatch) = exec_probe_mismatch(&stdout, &stderr, exit_status, eof, close) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, mismatch));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_probe_reports_each_mismatch_without_output_bytes() {
        let cases = [
            (
                &b"changed"[..],
                EXEC_PROBE_STDERR,
                Some(7),
                true,
                true,
                "stdout_match=false",
            ),
            (
                EXEC_PROBE_INPUT,
                &b"changed"[..],
                Some(7),
                true,
                true,
                "stderr_match=false",
            ),
            (
                EXEC_PROBE_INPUT,
                EXEC_PROBE_STDERR,
                Some(1),
                true,
                true,
                "exit_status=Some(1)",
            ),
            (
                EXEC_PROBE_INPUT,
                EXEC_PROBE_STDERR,
                Some(7),
                false,
                true,
                "eof=false",
            ),
            (
                EXEC_PROBE_INPUT,
                EXEC_PROBE_STDERR,
                Some(7),
                true,
                false,
                "close=false",
            ),
        ];

        for (stdout, stderr, status, eof, close, reason) in cases {
            let message = exec_probe_mismatch(stdout, stderr, status, eof, close)
                .expect("mismatch must be diagnosed");
            assert!(message.contains(reason), "{message}");
            assert!(message.contains(&format!("stdout_len={}", stdout.len())));
            assert!(message.contains(&format!("stderr_len={}", stderr.len())));
            assert!(!message.contains("changed"), "raw output leaked: {message}");
        }

        assert_eq!(
            exec_probe_mismatch(EXEC_PROBE_INPUT, EXEC_PROBE_STDERR, Some(7), true, true,),
            None
        );
    }

    #[test]
    fn exec_probe_command_uses_raw_clr2_streams_and_flushes() {
        assert!(EXEC_PROBE_COMMAND.contains("[Console]::OpenStandardError()"));
        assert!(EXEC_PROBE_COMMAND.contains("$o.Flush()"));
        assert!(EXEC_PROBE_COMMAND.contains("$e.Flush()"));
        assert!(EXEC_PROBE_COMMAND.contains("$e.Write($x,0,$x.Length)"));
        assert!(EXEC_PROBE_COMMAND.contains("exit 7"));
        assert!(!EXEC_PROBE_COMMAND.contains(".Error.Write"));
        assert!(!EXEC_PROBE_COMMAND.contains("CopyTo"));
    }
}
