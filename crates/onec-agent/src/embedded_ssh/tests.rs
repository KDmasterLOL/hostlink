use super::*;
use russh::ChannelMsg;
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh_sftp::client::SftpSession as SftpClient;
use russh_sftp::protocol::OpenFlags;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

#[derive(Clone)]
struct StrictTestHost {
    expected: PublicKey,
}

impl client::Handler for StrictTestHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(server_public_key.certificate().is_none()
            && server_public_key.public_key().key_data() == self.expected.key_data())
    }
}

struct RunningFixture {
    _dir: TempDir,
    address: std::net::SocketAddr,
    host_key: PublicKey,
    client_key: Arc<PrivateKey>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl RunningFixture {
    async fn stop(mut self) {
        self.shutdown
            .take()
            .expect("shutdown sender")
            .send(())
            .expect("server still running");
        let result = tokio::time::timeout(Duration::from_secs(6), self.task)
            .await
            .expect("embedded SSH shutdown deadline")
            .expect("embedded SSH task join");
        result.expect("embedded SSH server");
    }
}

async fn start_fixture() -> RunningFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host private key");
    let client_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client private key");
    let host_key_path = dir.path().join("ssh_host_ed25519_key");
    let host_public_key_path = dir.path().join("ssh_host_ed25519_key.pub");
    let authorized_keys_path = dir.path().join("sshd_authorized_keys");

    fs::write(
        &host_key_path,
        host_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host key encoding")
            .as_bytes(),
    )
    .expect("host key file");
    hostlink_core::restrict_private_file(&host_key_path).expect("private host key");
    fs::write(
        &host_public_key_path,
        format!(
            "{} host@test\n",
            host_key.public_key().to_openssh().expect("host public key")
        ),
    )
    .expect("host public key file");
    fs::write(
        &authorized_keys_path,
        format!(
            "{} controller@test\n",
            client_key
                .public_key()
                .to_openssh()
                .expect("client public key")
        ),
    )
    .expect("authorized keys");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("embedded SSH listener");
    let address = listener.local_addr().expect("listener address");
    let config = EmbeddedSshConfig::new("managed-user", host_key_path, authorized_keys_path);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(serve_until(listener, config, async move {
        let _ = shutdown_rx.await;
    }));

    RunningFixture {
        _dir: dir,
        address,
        host_key: host_key.public_key().clone(),
        client_key: Arc::new(client_key),
        shutdown: Some(shutdown_tx),
        task,
    }
}

async fn connect(
    fixture: &RunningFixture,
    expected_host_key: PublicKey,
) -> russh::client::Handle<StrictTestHost> {
    client::connect(
        Arc::new(client::Config::default()),
        fixture.address,
        StrictTestHost {
            expected: expected_host_key,
        },
    )
    .await
    .expect("SSH connect")
}

async fn authenticate(
    session: &mut russh::client::Handle<StrictTestHost>,
    user: &str,
    key: Arc<PrivateKey>,
) -> bool {
    session
        .authenticate_publickey(user.to_owned(), PrivateKeyWithHashAlg::new(key, None))
        .await
        .expect("public-key auth")
        .success()
}

async fn open_sftp(session: &russh::client::Handle<StrictTestHost>) -> SftpClient {
    let mut channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .request_subsystem(true, "sftp")
        .await
        .expect("SFTP subsystem request");

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("SFTP subsystem rejected"),
            Some(_) => {}
            None => panic!("SFTP channel closed before acknowledgement"),
        }
    }

    SftpClient::new(channel.into_stream())
        .await
        .expect("SFTP session")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_auth_sftp_forward_and_shutdown_round_trip() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        authenticate(&mut session, "managed-user", fixture.client_key.clone()).await,
        "enrolled controller key must authenticate"
    );

    let remote_path = fixture
        ._dir
        .path()
        .join("Каталог с пробелом")
        .join("Артефакт %.bin");
    fs::create_dir_all(remote_path.parent().expect("remote parent")).expect("remote parent");
    let remote_path = remote_path.to_string_lossy().to_string();
    let payload = b"embedded-russh-sftp-round-trip";

    let sftp = open_sftp(&session).await;
    assert!(
        !sftp
            .try_exists(remote_path.clone())
            .await
            .expect("missing path check")
    );
    let mut remote = sftp
        .open_with_flags(
            remote_path.clone(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
        .expect("SFTP staging create");
    remote.write_all(payload).await.expect("SFTP write");
    remote.close().await.expect("SFTP close");

    let metadata = sftp
        .metadata(remote_path.clone())
        .await
        .expect("SFTP metadata");
    assert_eq!(metadata.size, Some(payload.len() as u64));

    let mut remote = sftp.open(remote_path.clone()).await.expect("SFTP open");
    let mut restored = Vec::new();
    remote
        .read_to_end(&mut restored)
        .await
        .expect("SFTP download");
    remote.close().await.expect("SFTP download close");
    assert_eq!(restored, payload);
    sftp.remove_file(remote_path.clone())
        .await
        .expect("SFTP remove");
    assert!(
        !sftp
            .try_exists(remote_path)
            .await
            .expect("removed path check")
    );

    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo listener");
    let echo_port = echo_listener.local_addr().expect("echo address").port();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.expect("echo accept");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .await
            .expect("echo request after half-close");
        assert_eq!(request, b"ping");
        stream.write_all(b"pong").await.expect("echo response");
        stream.shutdown().await.expect("echo shutdown");
    });

    let channel = session
        .channel_open_direct_tcpip("localhost", echo_port.into(), "127.0.0.1", 0)
        .await
        .expect("direct-tcpip");
    let mut forwarded = channel.into_stream();
    forwarded.write_all(b"ping").await.expect("forward write");
    forwarded
        .shutdown()
        .await
        .expect("forward request half-close");
    let mut echoed = Vec::new();
    forwarded
        .read_to_end(&mut echoed)
        .await
        .expect("forward response after half-close");
    assert_eq!(echoed, b"pong");
    echo.await.expect("echo task");

    sftp.close().await.expect("close SFTP session");
    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_rejects_wrong_identity_user_and_host_key() {
    let fixture = start_fixture().await;
    let wrong_client = Arc::new(
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong client key"),
    );

    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        !authenticate(&mut session, "managed-user", wrong_client).await,
        "unknown key must be rejected"
    );
    assert!(
        !authenticate(&mut session, "other-user", fixture.client_key.clone()).await,
        "wrong username must be rejected"
    );

    let wrong_host =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong host key");
    let error = match client::connect(
        Arc::new(client::Config::default()),
        fixture.address,
        StrictTestHost {
            expected: wrong_host.public_key().clone(),
        },
    )
    .await
    {
        Ok(_) => panic!("host-key mismatch must fail closed"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("key") || error.to_string().contains("server"),
        "{error}"
    );

    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_keeps_shell_and_pty_requests_rejected() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        authenticate(&mut session, "managed-user", fixture.client_key.clone()).await,
        "enrolled controller key must authenticate"
    );

    let mut pty_channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    pty_channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("PTY request");
    loop {
        match tokio::time::timeout(Duration::from_secs(2), pty_channel.wait())
            .await
            .expect("PTY rejection deadline")
        {
            Some(ChannelMsg::Failure) => break,
            Some(ChannelMsg::Success) => panic!("PTY request must remain rejected"),
            Some(_) => {}
            None => panic!("rejected PTY channel closed without failure acknowledgement"),
        }
    }
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), pty_channel.wait())
            .await
            .expect("PTY channel close deadline"),
        Some(ChannelMsg::Close)
    ));

    let mut channel = session.channel_open_session().await.expect("shell channel");
    channel.request_shell(true).await.expect("shell request");
    loop {
        match tokio::time::timeout(Duration::from_secs(2), channel.wait())
            .await
            .expect("request rejection deadline")
        {
            Some(ChannelMsg::Failure) => break,
            Some(ChannelMsg::Success) => panic!("shell request must remain rejected"),
            Some(_) => {}
            None => panic!("rejected channel closed without an explicit failure"),
        }
    }
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), channel.wait())
            .await
            .expect("shell channel close deadline"),
        Some(ChannelMsg::Close)
    ));

    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_exec_streams_binary_stdin_stdout_stderr_and_exit_status() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);

    let channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .exec(
            true,
            "cat; printf '\\nstdout-tail'; printf 'stderr-bytes' >&2; exit 7",
        )
        .await
        .expect("exec request");
    let (mut channel_input, channel_output) = channel.split();
    let mut stdin = channel_output.make_writer();
    let payload: Vec<u8> = (0..256 * 1024).map(|index| index as u8).collect();
    stdin.write_all(&payload).await.expect("exec stdin bytes");
    stdin.flush().await.expect("exec stdin flush");
    channel_output.eof().await.expect("exec stdin EOF");
    drop(stdin);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    let mut saw_eof = false;
    let mut saw_close = false;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel_input.wait())
        .await
        .expect("exec output deadline")
    {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Eof => saw_eof = true,
            ChannelMsg::Close => {
                saw_close = true;
                break;
            }
            _ => {}
        }
    }
    assert_eq!(&stdout[..payload.len()], payload);
    assert_eq!(&stdout[payload.len()..], b"\nstdout-tail");
    assert_eq!(stderr, b"stderr-bytes");
    assert_eq!(exit_status, Some(7));
    assert!(saw_eof, "server must send EOF before closing the channel");
    assert!(saw_close, "server must close the completed exec channel");

    session
        .disconnect(russh::Disconnect::ByApplication, "exec complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_windows_exec_streams_binary_stdio_and_exit_status() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);

    let channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .exec(
            true,
            r#"$stdinStream = [Console]::OpenStandardInput(); $stdoutStream = [Console]::OpenStandardOutput(); $memory = New-Object System.IO.MemoryStream; $stdinStream.CopyTo($memory); $bytes = $memory.ToArray(); $stdoutStream.Write($bytes, 0, $bytes.Length); $stderrStream = [Console]::OpenStandardError(); $errorBytes = [byte[]](0, 255, 69, 82, 82, 13, 10); $stderrStream.Write($errorBytes, 0, $errorBytes.Length); exit 7"#,
        )
        .await
        .expect("exec request");
    let (mut channel_input, channel_output) = channel.split();
    let mut stdin = channel_output.make_writer();
    let payload: Vec<u8> = (0..4096).map(|index| (index * 37) as u8).collect();
    stdin.write_all(&payload).await.expect("exec stdin bytes");
    stdin.flush().await.expect("exec stdin flush");
    channel_output.eof().await.expect("exec stdin EOF");
    drop(stdin);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    let mut saw_eof = false;
    let mut saw_close = false;
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(message) = channel_input.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Eof => saw_eof = true,
                ChannelMsg::Close => {
                    assert!(saw_eof, "server must send EOF before closing the channel");
                    saw_close = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("Windows exec output deadline");

    assert_eq!(stdout, payload, "PowerShell must echo stdin byte-for-byte");
    let expected_stderr = [0_u8, 255, b'E', b'R', b'R', b'\r', b'\n'];
    assert_eq!(stderr, expected_stderr);
    assert_eq!(
        exit_status,
        Some(7),
        "exec must preserve the process exit code"
    );
    assert!(saw_eof, "server must send EOF before closing the channel");
    assert!(saw_close, "server must close the completed exec channel");

    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "Windows exec complete",
            "en",
        )
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_rejects_invalid_exec_command_strings() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);

    for command in [
        Vec::new(),
        b"\0invalid".to_vec(),
        vec![0xff],
        vec![b'x'; MAX_EXEC_COMMAND_BYTES + 1],
    ] {
        let mut channel = session
            .channel_open_session()
            .await
            .expect("session channel");
        channel.exec(true, command).await.expect("exec request");
        loop {
            match tokio::time::timeout(Duration::from_secs(2), channel.wait())
                .await
                .expect("exec rejection deadline")
            {
                Some(ChannelMsg::Failure) => break,
                Some(ChannelMsg::Success) => panic!("invalid SSH exec string was accepted"),
                Some(_) => {}
                None => panic!("invalid exec channel closed without failure acknowledgement"),
            }
        }
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), channel.wait())
                .await
                .expect("invalid exec channel close deadline"),
            Some(ChannelMsg::Close)
        ));
    }

    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "invalid exec complete",
            "en",
        )
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_nonexistent_fixed_command_returns_stderr_and_nonzero_status() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);

    let missing_executable = fixture
        ._dir
        .path()
        .join("onec_950_fixed_missing_executable");
    let command = format!("'{}'", missing_executable.display());
    let mut channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, command).await.expect("exec request");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("missing command deadline")
        {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.extend_from_slice(&data),
            Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
            Some(ChannelMsg::Close) => break,
            Some(_) => {}
            None => panic!("missing command channel did not finish"),
        }
    }
    assert!(stdout.is_empty(), "missing command must not write stdout");
    assert!(!stderr.is_empty(), "missing command must report on stderr");
    assert_eq!(
        exit_status,
        Some(127),
        "missing command must exit with shell status 127"
    );

    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "missing command complete",
            "en",
        )
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_bounds_concurrent_exec_sessions() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);

    let mut active = Vec::new();
    for _ in 0..MAX_ACTIVE_EXEC_SESSIONS {
        let channel = session
            .channel_open_session()
            .await
            .expect("session channel");
        channel
            .exec(true, "cat >/dev/null")
            .await
            .expect("exec request");
        let (mut reader, writer) = channel.split();
        assert!(matches!(reader.wait().await, Some(ChannelMsg::Success)));
        active.push((reader, writer));
    }

    let mut rejected = session
        .channel_open_session()
        .await
        .expect("overflow channel");
    rejected
        .exec(true, "cat >/dev/null")
        .await
        .expect("exec request");
    loop {
        match tokio::time::timeout(Duration::from_secs(2), rejected.wait())
            .await
            .expect("exec concurrency deadline")
        {
            Some(ChannelMsg::Failure) => break,
            Some(ChannelMsg::Success) => panic!("exec above concurrency limit was accepted"),
            Some(_) => {}
            None => panic!("rejected exec channel closed without failure acknowledgement"),
        }
    }
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), rejected.wait())
            .await
            .expect("overflow exec channel close deadline"),
        Some(ChannelMsg::Close)
    ));

    for (_, writer) in &active {
        writer.close().await.expect("close active exec channel");
    }
    drop(active);
    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "exec bound complete",
            "en",
        )
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_disconnect_kills_exec_process_tree() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);
    let pid_path = fixture._dir.path().join("child.pid");
    let command = background_child_pid_command(&pid_path);
    let mut channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel.exec(true, command).await.expect("exec request");
    loop {
        match tokio::time::timeout(Duration::from_secs(2), channel.wait())
            .await
            .expect("exec start acknowledgement deadline")
        {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("exec request was rejected"),
            Some(_) => {}
            None => panic!("exec channel closed before acknowledgement"),
        }
    }
    let child_pid = wait_for_linux_pid(&pid_path).await;

    session
        .disconnect(russh::Disconnect::ByApplication, "cancel exec", "en")
        .await
        .expect("SSH disconnect");
    wait_for_linux_process_exit(child_pid, "client disconnect").await;
    fixture.stop().await;
}

#[cfg(all(unix, target_os = "linux"))]
fn background_child_pid_command(pid_path: &std::path::Path) -> String {
    format!(
        "sleep 60 </dev/null >/dev/null 2>&1 & child=$!; printf '%s' \"$child\" > {}; wait",
        pid_path.display()
    )
}

#[cfg(all(unix, target_os = "linux"))]
async fn wait_for_linux_pid(pid_path: &std::path::Path) -> libc::pid_t {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(pid) = tokio::fs::read_to_string(pid_path).await
                && let Ok(pid) = pid.parse::<libc::pid_t>()
            {
                break pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("child PID publication deadline")
}

#[cfg(all(unix, target_os = "linux"))]
async fn wait_for_linux_process_exit(pid: libc::pid_t, reason: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !linux_process_is_running(pid) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("exec descendant must exit after {reason}"));
}

#[cfg(all(unix, target_os = "linux"))]
fn linux_process_is_running(pid: libc::pid_t) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    !stat
        .rsplit_once(')')
        .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_exec_timeout_kills_process_tree_without_exit_status() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);
    let pid_path = fixture._dir.path().join("timed-out-child.pid");
    let mut channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .exec(true, background_child_pid_command(&pid_path))
        .await
        .expect("exec request");

    loop {
        match tokio::time::timeout(Duration::from_secs(2), channel.wait())
            .await
            .expect("exec start acknowledgement deadline")
        {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("exec request was rejected"),
            Some(_) => {}
            None => panic!("exec channel closed before acknowledgement"),
        }
    }
    let child_pid = wait_for_linux_pid(&pid_path).await;

    let mut saw_eof = false;
    let mut exit_status = None;
    loop {
        match tokio::time::timeout(Duration::from_secs(8), channel.wait())
            .await
            .expect("exec timeout deadline")
        {
            Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
            Some(ChannelMsg::Eof) => saw_eof = true,
            Some(ChannelMsg::Close) => break,
            Some(_) => {}
            None => panic!("timed-out exec channel did not close"),
        }
    }
    assert!(saw_eof, "timed-out process channel must send EOF");
    assert_eq!(
        exit_status, None,
        "timeout must not fabricate a process exit code"
    );
    wait_for_linux_process_exit(child_pid, "timeout").await;
    session
        .disconnect(
            russh::Disconnect::ByApplication,
            "exec timeout complete",
            "en",
        )
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[cfg(all(unix, target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_shutdown_cancels_exec_process_tree() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(authenticate(&mut session, "managed-user", fixture.client_key.clone()).await);
    let pid_path = fixture._dir.path().join("shutdown-child.pid");
    let mut channel = session
        .channel_open_session()
        .await
        .expect("session channel");
    channel
        .exec(true, background_child_pid_command(&pid_path))
        .await
        .expect("exec request");
    loop {
        match tokio::time::timeout(Duration::from_secs(2), channel.wait())
            .await
            .expect("exec start acknowledgement deadline")
        {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("exec request was rejected"),
            Some(_) => {}
            None => panic!("exec channel closed before acknowledgement"),
        }
    }
    let child_pid = wait_for_linux_pid(&pid_path).await;
    fixture.stop().await;
    wait_for_linux_process_exit(child_pid, "server shutdown").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_bounds_active_sftp_sessions_and_open_files() {
    use russh_sftp::server::Handler as _;

    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        authenticate(&mut session, "managed-user", fixture.client_key.clone()).await,
        "enrolled controller key must authenticate"
    );

    let mut active = Vec::new();
    for _ in 0..MAX_ACTIVE_SFTP_SESSIONS {
        active.push(open_sftp(&session).await);
    }

    let mut rejected = session
        .channel_open_session()
        .await
        .expect("session channel for rejected SFTP request");
    rejected
        .request_subsystem(true, "sftp")
        .await
        .expect("SFTP subsystem request");
    loop {
        match rejected.wait().await {
            Some(ChannelMsg::Failure) => break,
            Some(ChannelMsg::Success) => panic!("SFTP session above the active bound was accepted"),
            Some(_) => {}
            None => panic!("rejected SFTP channel closed without failure acknowledgement"),
        }
    }

    let file_root = fixture._dir.path().join("file-handle-bound");
    fs::create_dir_all(&file_root).expect("file-handle root");
    let slot = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("SFTP test slot");
    let mut handler = super::sftp::SftpSession::new(slot);
    let mut handles = Vec::new();
    for index in 0..super::sftp::MAX_OPEN_FILES {
        let path = file_root.join(format!("file-{index}.bin"));
        let handle = handler
            .open(
                index as u32,
                path.to_string_lossy().into_owned(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                Default::default(),
            )
            .await
            .expect("file handle within bound");
        handles.push(handle.handle);
    }
    let error = handler
        .open(
            u32::MAX,
            file_root
                .join("overflow.bin")
                .to_string_lossy()
                .into_owned(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            Default::default(),
        )
        .await
        .expect_err("file handle above the per-session bound must fail");
    assert_eq!(error, russh_sftp::protocol::StatusCode::Failure);

    for (index, handle) in handles.into_iter().enumerate() {
        handler
            .close(index as u32, handle)
            .await
            .expect("close bounded file handle");
    }
    for sftp in active {
        sftp.close().await.expect("close active SFTP session");
    }
    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_bounds_pending_session_channels() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        authenticate(&mut session, "managed-user", fixture.client_key.clone()).await,
        "enrolled controller key must authenticate"
    );

    let mut channels = Vec::new();
    for _ in 0..MAX_PENDING_SESSION_CHANNELS {
        channels.push(
            session
                .channel_open_session()
                .await
                .expect("pending session channel within bound"),
        );
    }
    assert!(
        session.channel_open_session().await.is_err(),
        "session channel above the bound must be rejected"
    );

    drop(channels);
    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
}

#[test]
fn embedded_server_key_material_is_bounded_private_and_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_key_path = dir.path().join("host");
    let authorized_keys_path = dir.path().join("authorized");

    fs::write(&host_key_path, vec![b'x'; HOST_KEY_MAX_BYTES + 1]).expect("oversized host");
    hostlink_core::restrict_private_file(&host_key_path).expect("private oversized host");
    let error = load_host_key(&host_key_path).expect_err("oversized host key must fail");
    assert!(
        error.to_string().contains("exceeds") || error.to_string().contains("limit"),
        "{error}"
    );

    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("valid host key");
    fs::write(
        &host_key_path,
        host.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host encoding")
            .as_bytes(),
    )
    .expect("host key");
    hostlink_core::restrict_private_file(&host_key_path).expect("private host key");
    load_host_key(&host_key_path).expect("valid private host key");

    let encrypted = host
        .encrypt(&mut rand::rng(), b"fixture-passphrase")
        .expect("encrypted host key");
    fs::write(
        &host_key_path,
        encrypted
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encrypted host encoding")
            .as_bytes(),
    )
    .expect("encrypted host key file");
    hostlink_core::restrict_private_file(&host_key_path).expect("private encrypted host key");
    let error = load_host_key(&host_key_path).expect_err("encrypted host key must fail closed");
    assert!(error.to_string().contains("unencrypted"), "{error}");

    fs::write(&authorized_keys_path, "not-an-ssh-key\n").expect("malformed authorized keys");
    assert!(
        load_authorized_keys(&authorized_keys_path).is_err(),
        "malformed authorized key must fail"
    );
    fs::write(&authorized_keys_path, "# comments only\n\n").expect("empty authorized keys");
    assert!(
        load_authorized_keys(&authorized_keys_path).is_err(),
        "empty authorization set must fail"
    );

    let client =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("valid client key");
    fs::write(
        &authorized_keys_path,
        format!(
            "no-port-forwarding {} controller@test\n",
            client.public_key().to_openssh().expect("client public key")
        ),
    )
    .expect("option-bearing authorized keys");
    let error = load_authorized_keys(&authorized_keys_path)
        .expect_err("sshd-specific authorized-key options must fail closed");
    assert!(error.to_string().contains("options"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_candidate_preflight_exercises_exact_transport_surface() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
    let host_key_path = dir.path().join("ssh_host_ed25519_key");
    let host_public_key_path = dir.path().join("ssh_host_ed25519_key.pub");
    let authorized_keys_path = dir.path().join("sshd_authorized_keys");
    let identity_path = dir.path().join("id_ed25519");

    fs::write(
        &host_key_path,
        host.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host encoding")
            .as_bytes(),
    )
    .expect("host key");
    hostlink_core::restrict_private_file(&host_key_path).expect("private host key");
    fs::write(
        &host_public_key_path,
        format!(
            "{} host@test\n",
            host.public_key().to_openssh().expect("host public key")
        ),
    )
    .expect("host public key file");
    fs::write(
        &authorized_keys_path,
        format!(
            "{} controller@test\n",
            controller
                .public_key()
                .to_openssh()
                .expect("controller public key")
        ),
    )
    .expect("authorized keys");
    fs::write(
        &identity_path,
        controller
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("controller identity encoding")
            .as_bytes(),
    )
    .expect("controller identity");
    hostlink_core::restrict_private_file(&identity_path).expect("private controller identity");

    let occupied_runtime_port =
        std::net::TcpListener::bind("127.0.0.1:0").expect("occupied final runtime port");
    let port = occupied_runtime_port
        .local_addr()
        .expect("occupied runtime port")
        .port();

    let config = crate::EmbeddedSshServerConfig {
        user: "managed-user".to_owned(),
        host_key: host_key_path,
        authorized_keys: authorized_keys_path,
        port,
    };
    preflight_embedded_ssh(&config, &host_public_key_path, &identity_path, dir.path())
        .await
        .expect("embedded SSH candidate preflight");

    let wrong_host =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong host key");
    fs::write(
        &host_public_key_path,
        wrong_host
            .public_key()
            .to_openssh()
            .expect("wrong host public key"),
    )
    .expect("mismatched host public key file");
    let error = preflight_embedded_ssh(&config, &host_public_key_path, &identity_path, dir.path())
        .await
        .expect_err("mismatched advertised host key must fail closed");
    assert!(error.to_string().contains("does not match"), "{error}");

    let leftovers = fs::read_dir(dir.path())
        .expect("scratch directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("onec embedded ssh проверка ")
        })
        .count();
    assert_eq!(leftovers, 0, "preflight scratch file must be removed");
}

#[test]
fn embedded_preflight_does_not_own_a_tokio_runtime() {
    let preflight = include_str!("preflight.rs");
    assert!(
        !preflight.contains("tokio::runtime::Builder"),
        "embedded preflight must reuse the application runtime"
    );
    assert!(
        !preflight.contains(".block_on("),
        "embedded preflight must stay async end-to-end"
    );

    let cli = include_str!("../main.rs");
    assert!(cli.contains("fn run_embedded_ssh_preflight_cli"));
    assert!(cli.contains("fn run_embedded_ssh_preflight_command"));
    assert!(cli.contains("tokio::runtime::Builder::new_multi_thread()"));
    assert!(cli.contains(".block_on(run_embedded_ssh_preflight_command(args))"));
    assert!(cli.contains("preflight_embedded_ssh("));
    assert!(cli.contains(".await"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_server_refuses_non_loopback_listener() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let client = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key_path = dir.path().join("host");
    let authorized_keys_path = dir.path().join("authorized");

    fs::write(
        &host_key_path,
        host.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host encoding")
            .as_bytes(),
    )
    .expect("host key");
    hostlink_core::restrict_private_file(&host_key_path).expect("private host key");
    fs::write(
        &authorized_keys_path,
        client.public_key().to_openssh().expect("client public key"),
    )
    .expect("authorized keys");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("wildcard listener");
    let error = serve_until(
        listener,
        EmbeddedSshConfig::new("managed-user", host_key_path, authorized_keys_path),
        std::future::pending(),
    )
    .await
    .expect_err("wildcard listener must fail closed");
    assert!(error.to_string().contains("loopback-only"), "{error}");
}
