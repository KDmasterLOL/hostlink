//! Real Agent + Client direct-tcpip forwarding and CLI probe interop.

use hostlink::{HostSpec, connect::HostConnection, forward};
use hostlink_agent::{AgentConfig, ssh};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

fn private_file(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).expect("write private test key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private test key ACL");
    }
    #[cfg(windows)]
    protect_windows_fixture(path, false);
}

fn private_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private directory ACL");
    }
    #[cfg(windows)]
    protect_windows_fixture(path, true);
}

#[cfg(windows)]
fn protect_windows_fixture(path: &std::path::Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current = windows_permissions::utilities::current_process_sid().expect("current SID");
    let sid = ConvertSidToStringSid(&current).expect("format current Windows SID");
    let flags = if directory { "OICI" } else { "" };
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;{flags};FA;;;{})", sid.to_string_lossy())
            .parse()
            .expect("construct private fixture ACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(current.as_ref()),
        None,
        descriptor.dacl(),
        None,
    )
    .expect("protect current-user fixture");
}

struct Fixture {
    root: tempfile::TempDir,
    spec: HostSpec,
    listener: SocketAddr,
    stop_agent: Option<tokio::sync::oneshot::Sender<()>>,
    agent_task: Option<JoinHandle<std::io::Result<()>>>,
    stop_echo: Option<tokio::sync::oneshot::Sender<()>>,
    echo_task: Option<JoinHandle<()>>,
    active_targets: Arc<AtomicUsize>,
}

struct ActiveTarget(Arc<AtomicUsize>);

impl Drop for ActiveTarget {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Fixture {
    async fn start() -> Self {
        let root = tempfile::tempdir().expect("temporary integration directory");
        private_directory(root.path());
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let controller =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
        let host_key_path = root.path().join("host-key");
        let identity = root.path().join("controller-key");
        let authorized_keys = root.path().join("authorized_keys");
        let jobs_root = root.path().join("jobs");
        fs::create_dir(&jobs_root).expect("jobs root");
        private_directory(&jobs_root);
        hostlink_agent::durable::DurableStore::initialize_fresh(&jobs_root)
            .await
            .expect("initialize fresh private Agent SQLite fixture")
            .close()
            .await;
        private_file(
            &host_key_path,
            host_key
                .to_openssh(LineEnding::LF)
                .expect("encode host key")
                .as_bytes(),
        );
        private_file(
            &identity,
            controller
                .to_openssh(LineEnding::LF)
                .expect("encode controller key")
                .as_bytes(),
        );
        private_file(
            &authorized_keys,
            format!(
                "{} tcp-forward-test\n",
                controller.public_key().to_openssh().unwrap()
            )
            .as_bytes(),
        );

        let agent_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Agent listener");
        let listener = agent_listener.local_addr().expect("Agent address");
        let config = AgentConfig {
            listen: listener,
            user: "hostlink".into(),
            host_key: host_key_path,
            authorized_keys,
            jobs_root,
            gateway: None,
            gateway_alternates: Vec::new(),
        };
        let (stop_agent, stop_agent_rx) = tokio::sync::oneshot::channel();
        let agent_task = tokio::spawn(async move {
            ssh::serve_on(agent_listener, &config, async {
                let _ = stop_agent_rx.await;
            })
            .await
        });

        let echo_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo listener");
        let echo_address = echo_listener.local_addr().expect("echo address");
        let (stop_echo, mut stop_echo_rx) = tokio::sync::oneshot::channel();
        let active_targets = Arc::new(AtomicUsize::new(0));
        let active_counter = active_targets.clone();
        let echo_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_echo_rx => break,
                    accepted = echo_listener.accept() => {
                        let Ok((mut socket, _)) = accepted else { break };
                        active_counter.fetch_add(1, Ordering::Relaxed);
                        let connection_counter = active_counter.clone();
                        tokio::spawn(async move {
                            let _active = ActiveTarget(connection_counter);
                            let (mut reader, mut writer) = socket.split();
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        });
                    }
                }
            }
        });

        let spec = HostSpec {
            endpoint: listener,
            user: "hostlink".into(),
            identity,
            host_public_key: host_key.public_key().to_openssh().expect("format host pin"),
            gateway: None,
        };
        Self {
            root,
            spec,
            listener: echo_address,
            stop_agent: Some(stop_agent),
            agent_task: Some(agent_task),
            stop_echo: Some(stop_echo),
            echo_task: Some(echo_task),
            active_targets,
        }
    }

    fn config_path(&self) -> std::path::PathBuf {
        let path = self.root.path().join("host.json");
        let config = serde_json::json!({
            "endpoint": self.spec.endpoint,
            "user": &self.spec.user,
            "identity": &self.spec.identity,
            "host_public_key": &self.spec.host_public_key,
            "gateway": null,
        });
        fs::write(
            &path,
            serde_json::to_vec(&config).expect("serialize host config"),
        )
        .expect("write host config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("config ACL");
        }
        path
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop_agent.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.agent_task.take() {
            tokio::time::timeout(Duration::from_secs(7), task)
                .await
                .expect("Agent shutdown deadline")
                .expect("Agent task join")
                .expect("Agent server shutdown");
        }
        if let Some(stop) = self.stop_echo.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.echo_task.take() {
            task.await.expect("echo task join");
        }
    }
}

#[tokio::test]
async fn local_forward_roundtrips_binary_data_for_multiple_clients_and_joins() {
    let fixture = Fixture::start().await;
    let connection = HostConnection::connect(&fixture.spec)
        .await
        .expect("pinned SSH connect");
    let server = forward::start_local_forward(
        connection,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        fixture.listener,
    )
    .await
    .expect("start loopback forward");
    let local = server.local_addr();

    tokio::join!(
        roundtrip(local, 0),
        roundtrip(local, 1),
        roundtrip(local, 2),
        roundtrip(local, 3),
    );

    let mut held = Vec::with_capacity(16);
    for _ in 0..16 {
        held.push(
            TcpStream::connect(local)
                .await
                .expect("open bounded proxy slot"),
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.active_targets.load(Ordering::Relaxed) < 16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all 16 permitted channels reached the target");
    let mut excess = TcpStream::connect(local)
        .await
        .expect("accept excess local socket");
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), excess.read(&mut byte))
        .await
        .expect("excess connection close deadline")
        .expect("read excess connection close");
    assert_eq!(read, 0, "connection over the limit must be closed");
    assert_eq!(fixture.active_targets.load(Ordering::Relaxed), 16);
    drop(held);

    server.shutdown().await.expect("joined forward shutdown");
    assert!(
        TcpStream::connect(local).await.is_err(),
        "listener was retained after shutdown"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn probe_cli_succeeds_and_reports_refused_target_and_wrong_pin() {
    let fixture = Fixture::start().await;
    let config = fixture.config_path();
    let binary = env!("CARGO_BIN_EXE_hostlink");
    // Do not block Tokio's current-thread executor while the in-process SSH
    // Agent must accept and process the CLI's connection.
    let success = tokio::process::Command::new(binary)
        .args(["probe", "--config"])
        .arg(&config)
        .args(["--target", &fixture.listener.to_string()])
        .output()
        .await
        .expect("run successful CLI probe");
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );

    let refused = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("refused test port");
    let refused_address = refused.local_addr().unwrap();
    drop(refused);
    let denied = tokio::process::Command::new(binary)
        .args(["probe", "--config"])
        .arg(&config)
        .args([
            "--target",
            &refused_address.to_string(),
            "--timeout-ms",
            "1500",
        ])
        .output()
        .await
        .expect("run refused CLI probe");
    assert!(!denied.status.success(), "refused TCP target must fail");
    let denied_text = String::from_utf8_lossy(&denied.stderr);
    assert!(!denied_text.contains("TCP probe succeeded"));
    assert!(
        !denied_text.is_empty(),
        "refusal must explain why the probe failed"
    );

    let mut wrong_pin = fixture.spec.clone();
    let wrong_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong pin key");
    wrong_pin.host_public_key = wrong_key
        .public_key()
        .to_openssh()
        .expect("format wrong pin");
    assert!(
        HostConnection::connect(&wrong_pin).await.is_err(),
        "wrong host pin was accepted"
    );
    fixture.stop().await;
}

#[test]
fn cli_rejects_public_or_invalid_forward_and_probe_addresses_before_connecting() {
    let binary = env!("CARGO_BIN_EXE_hostlink");
    let public = Command::new(binary)
        .args([
            "forward",
            "--config",
            "missing.json",
            "--listen",
            "0.0.0.0:8080",
            "--target",
            "127.0.0.1:80",
        ])
        .output()
        .expect("check public bind rejection");
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("loopback"));

    let zero_listen = Command::new(binary)
        .args([
            "forward",
            "--config",
            "missing.json",
            "--listen",
            "127.0.0.1:0",
            "--target",
            "127.0.0.1:80",
        ])
        .output()
        .expect("check zero listen rejection");
    assert!(!zero_listen.status.success());

    let zero_deadline = Command::new(binary)
        .args([
            "probe",
            "--config",
            "missing.json",
            "--target",
            "127.0.0.1:80",
            "--timeout-ms",
            "0",
        ])
        .output()
        .expect("check zero deadline rejection");
    assert!(!zero_deadline.status.success());

    let zero_target = Command::new(binary)
        .args([
            "probe",
            "--config",
            "missing.json",
            "--target",
            "127.0.0.1:0",
        ])
        .output()
        .expect("check zero target port rejection");
    assert!(!zero_target.status.success());
}

#[tokio::test]
async fn forward_requires_loopback_and_active_agent_shutdown_closes_proxy() {
    let fixture = Fixture::start().await;
    let public = "192.0.2.10:9000".parse().unwrap();
    assert!(forward::validate_forward_listen(public, false).is_err());
    assert!(forward::validate_forward_listen("127.0.0.1:0".parse().unwrap(), false).is_err());
    assert!(forward::validate_forward_listen("127.0.0.1:0".parse().unwrap(), true).is_ok());

    let connection = HostConnection::connect(&fixture.spec)
        .await
        .expect("pinned SSH connect");
    let server =
        forward::start_local_forward(connection, "127.0.0.1:0".parse().unwrap(), fixture.listener)
            .await
            .expect("start local forward");
    let local = server.local_addr();
    let mut connected = TcpStream::connect(local)
        .await
        .expect("connect proxy client");
    let stop_agent = fixture.stop_agent.expect("Agent stop sender");
    stop_agent.send(()).expect("request Agent stop");
    let mut byte = [0_u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(3), connected.read(&mut byte)).await;
    server
        .shutdown()
        .await
        .expect("proxy closes after Agent shutdown");
    assert!(
        TcpStream::connect(local).await.is_err(),
        "listener remained after Agent shutdown"
    );
    if let Some(task) = fixture.agent_task {
        tokio::time::timeout(Duration::from_secs(7), task)
            .await
            .expect("Agent task shutdown deadline")
            .expect("Agent task join")
            .expect("Agent server stop");
    }
    if let Some(stop) = fixture.stop_echo {
        let _ = stop.send(());
    }
    if let Some(task) = fixture.echo_task {
        task.await.expect("echo task join");
    }
}

async fn roundtrip(address: SocketAddr, index: usize) {
    let mut socket = TcpStream::connect(address)
        .await
        .expect("local proxy connect");
    let payload: Vec<u8> = (0..4096).map(|byte| (byte * 31 + index) as u8).collect();
    socket
        .write_all(&payload)
        .await
        .expect("send binary payload");
    let mut actual = vec![0; payload.len()];
    socket
        .read_exact(&mut actual)
        .await
        .expect("read echo payload");
    assert_eq!(actual, payload);
}
