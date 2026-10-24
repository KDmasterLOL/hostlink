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
    onec_core::restrict_private_file(&host_key_path).expect("private host key");
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
async fn embedded_server_keeps_shell_and_exec_requests_rejected() {
    let fixture = start_fixture().await;
    let mut session = connect(&fixture, fixture.host_key.clone()).await;
    assert!(
        authenticate(&mut session, "managed-user", fixture.client_key.clone()).await,
        "enrolled controller key must authenticate"
    );

    for command in [None, Some(b"echo must-not-run".as_slice())] {
        let channel = session
            .channel_open_session()
            .await
            .expect("session channel");
        if let Some(command) = command {
            channel.exec(true, command).await.expect("exec request");
        } else {
            channel.request_shell(true).await.expect("shell request");
        }

        let mut channel = channel;
        loop {
            match tokio::time::timeout(Duration::from_secs(2), channel.wait())
                .await
                .expect("request rejection deadline")
            {
                Some(ChannelMsg::Failure) => break,
                Some(ChannelMsg::Success) => panic!("shell/exec request must remain rejected"),
                Some(_) => {}
                None => panic!("channel closed without an explicit rejection"),
            }
        }
    }

    session
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("SSH disconnect");
    fixture.stop().await;
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
    onec_core::restrict_private_file(&host_key_path).expect("private oversized host");
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
    onec_core::restrict_private_file(&host_key_path).expect("private host key");
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
    onec_core::restrict_private_file(&host_key_path).expect("private encrypted host key");
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
    onec_core::restrict_private_file(&host_key_path).expect("private host key");
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
    onec_core::restrict_private_file(&identity_path).expect("private controller identity");

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
    onec_core::restrict_private_file(&host_key_path).expect("private host key");
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
