use super::proxy::ProxyStdoutSink;
use super::*;
use processkit::RawOutputSink;
use russh::keys::PrivateKey;
use russh::server::{self, Auth, Server as _};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};

#[derive(Clone)]
struct TestGateway {
    client_key: russh::keys::PublicKey,
    listener: Arc<Mutex<Option<tokio::net::TcpListener>>>,
}

struct TestGatewaySession {
    client_key: russh::keys::PublicKey,
    listener: Arc<Mutex<Option<tokio::net::TcpListener>>>,
}

impl server::Server for TestGateway {
    type Handler = TestGatewaySession;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        TestGatewaySession {
            client_key: self.client_key.clone(),
            listener: Arc::clone(&self.listener),
        }
    }
}

impl server::Handler for TestGatewaySession {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if public_key.key_data() == self.client_key.key_data() {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if address != "127.0.0.1" {
            return Ok(false);
        }
        let mut listener_slot = self.listener.lock().await;
        let Some(listener) = listener_slot.take() else {
            return Ok(false);
        };
        let expected_port = listener.local_addr().map_err(russh::Error::IO)?.port();
        if *port != u32::from(expected_port) {
            return Ok(false);
        }
        let handle = session.handle();
        tokio::spawn(async move {
            while let Ok((mut stream, peer)) = listener.accept().await {
                let Ok(channel) = handle
                    .channel_open_forwarded_tcpip(
                        "127.0.0.1",
                        u32::from(expected_port),
                        peer.ip().to_string(),
                        u32::from(peer.port()),
                    )
                    .await
                else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut channel.into_stream())
                        .await;
                });
            }
        });
        Ok(true)
    }
}

pub(crate) struct GatewayFixture {
    _dir: tempfile::TempDir,
    gateway_host: String,
    host_public_key: String,
    ssh_address: SocketAddr,
    remote_port: u16,
    identity: PathBuf,
    known_hosts: PathBuf,
    forward_listener: Arc<Mutex<Option<tokio::net::TcpListener>>>,
    server_task: JoinHandle<io::Result<()>>,
}

impl GatewayFixture {
    pub(crate) fn abort_server(&self) {
        self.server_task.abort();
    }

    pub(crate) fn remote_port(&self) -> u16 {
        self.remote_port
    }

    pub(crate) async fn wait_forward_requested(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.forward_listener.lock().await.is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reverse forward request deadline");
    }
}

async fn start_gateway(client_key: &PrivateKey, known_host_key: &PrivateKey) -> GatewayFixture {
    start_gateway_at(client_key, known_host_key, [127, 0, 0, 1].into(), None).await
}

async fn start_gateway_at(
    client_key: &PrivateKey,
    known_host_key: &PrivateKey,
    bind_ip: std::net::Ipv4Addr,
    remote_port: Option<u16>,
) -> GatewayFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("client key encoding"),
    )
    .expect("identity");
    hostlink_core::restrict_private_file(&identity).expect("private identity");

    let remote_listener =
        tokio::net::TcpListener::bind(SocketAddr::from((bind_ip, remote_port.unwrap_or(0))))
            .await
            .expect("remote forward listener");
    let remote_port = remote_listener.local_addr().expect("remote address").port();
    let ssh_listener = tokio::net::TcpListener::bind(SocketAddr::from((bind_ip, 0)))
        .await
        .expect("SSH listener");
    let ssh_address = ssh_listener.local_addr().expect("SSH address");
    let known_hosts = dir.path().join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "[{}]:{} {}\n",
            bind_ip,
            ssh_address.port(),
            known_host_key
                .public_key()
                .to_openssh()
                .expect("host public key")
        ),
    )
    .expect("known hosts");

    let config = Arc::new(server::Config {
        keys: vec![known_host_key.clone()],
        nodelay: true,
        ..Default::default()
    });
    let forward_listener = Arc::new(Mutex::new(Some(remote_listener)));
    let mut server = TestGateway {
        client_key: client_key.public_key().clone(),
        listener: Arc::clone(&forward_listener),
    };
    let server_task =
        tokio::spawn(async move { server.run_on_socket(config, &ssh_listener).await });

    GatewayFixture {
        _dir: dir,
        gateway_host: bind_ip.to_string(),
        host_public_key: known_host_key
            .public_key()
            .to_openssh()
            .expect("host public key")
            .to_owned(),
        ssh_address,
        remote_port,
        identity,
        known_hosts,
        forward_listener,
        server_task,
    }
}

async fn echo_listener() -> (u16, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo listener");
    let port = listener.local_addr().expect("echo address").port();
    let task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut bytes = [0u8; 64];
            if let Ok(read) = stream.read(&mut bytes).await {
                let _ = stream.write_all(&bytes[..read]).await;
            }
        }
    });
    (port, task)
}

fn tunnel_config(fixture: &GatewayFixture) -> SshTunnelConfig {
    SshTunnelConfig {
        program: None,
        gateways: vec![SshGatewayEndpoint {
            host: fixture.gateway_host.clone(),
            user: "agent".to_owned(),
            port: fixture.ssh_address.port(),
            tls_proxy: None,
        }],
        remote_port: fixture.remote_port,
        identity: Some(fixture.identity.clone()),
        known_hosts: Some(fixture.known_hosts.clone()),
        reconnect_seconds: 1,
    }
}

pub(crate) async fn stable_fixture() -> (GatewayFixture, SshTunnelConfig) {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let fixture = start_gateway(&client_key, &host_key).await;
    let config = tunnel_config(&fixture);
    (fixture, config)
}

pub(crate) async fn active_active_fixture() -> (GatewayFixture, GatewayFixture, SshTunnelConfig) {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let first_host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("first host key");
    let second_host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("second host key");
    let first = start_gateway_at(&client_key, &first_host_key, [127, 0, 0, 2].into(), None).await;
    let second = start_gateway_at(
        &client_key,
        &second_host_key,
        [127, 0, 0, 3].into(),
        Some(first.remote_port),
    )
    .await;
    fs::write(
        &first.known_hosts,
        format!(
            "[{}]:{} {}\n[{}]:{} {}\n",
            first.gateway_host,
            first.ssh_address.port(),
            first_host_key
                .public_key()
                .to_openssh()
                .expect("first host key"),
            second.gateway_host,
            second.ssh_address.port(),
            second_host_key
                .public_key()
                .to_openssh()
                .expect("second host key"),
        ),
    )
    .expect("combined pinned known_hosts");
    let config = SshTunnelConfig {
        program: None,
        gateways: vec![
            SshGatewayEndpoint {
                host: first.gateway_host.clone(),
                user: "agent".to_owned(),
                port: first.ssh_address.port(),
                tls_proxy: None,
            },
            SshGatewayEndpoint {
                host: second.gateway_host.clone(),
                user: "agent".to_owned(),
                port: second.ssh_address.port(),
                tls_proxy: None,
            },
        ],
        remote_port: first.remote_port,
        identity: Some(first.identity.clone()),
        known_hosts: Some(first.known_hosts.clone()),
        reconnect_seconds: 1,
    };
    (first, second, config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_independent_gateway_fixtures_forward_the_same_remote_port() {
    let (first_fixture, second_fixture, config) = active_active_fixture().await;
    assert_eq!(first_fixture.remote_port, second_fixture.remote_port);
    let local = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local echo listener");
    let local_port = local.local_addr().expect("local echo address").port();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = local.accept().await.expect("accepted forwarded stream");
            tokio::spawn(async move {
                let mut bytes = [0_u8; 32];
                if let Ok(read) = stream.read(&mut bytes).await {
                    let _ = stream.write_all(&bytes[..read]).await;
                }
            });
        }
    });
    let mut first = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("first gateway tunnel");
    let mut second = ReverseTunnel::connect(
        &config,
        &config.gateways[1],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("second gateway tunnel");

    for gateway in &config.gateways {
        let mut remote =
            tokio::net::TcpStream::connect((gateway.host.as_str(), config.remote_port))
                .await
                .expect("same remote port is open on independent gateway");
        remote
            .write_all(b"multi-edge")
            .await
            .expect("write forwarded bytes");
        let mut echoed = [0; 10];
        remote
            .read_exact(&mut echoed)
            .await
            .expect("read forwarded bytes");
        assert_eq!(&echoed, b"multi-edge");
    }
    first.shutdown().await.expect("first tunnel shutdown");
    second.shutdown().await.expect("second tunnel shutdown");
    echo.await.expect("echo listener task");
    first_fixture.abort_server();
    second_fixture.abort_server();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_inv_222_reverse_tunnel_embedded_sftp_large_transfer_does_not_starve_concurrent_channel()
 {
    let (fixture, config) = stable_fixture().await;
    let dir = tempfile::tempdir().expect("embedded SSH fixture directory");
    let host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("embedded host key");
    let controller_key = Arc::new(
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("embedded controller key"),
    );
    let host_key_path = dir.path().join("ssh_host_ed25519_key");
    let authorized_keys_path = dir.path().join("authorized_keys");
    fs::write(
        &host_key_path,
        host_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host key encoding"),
    )
    .expect("write embedded host key");
    hostlink_core::restrict_private_file(&host_key_path).expect("restrict host key");
    fs::write(
        &authorized_keys_path,
        controller_key
            .public_key()
            .to_openssh()
            .expect("controller public key"),
    )
    .expect("write embedded authorized keys");

    let embedded_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind embedded SSH endpoint");
    let embedded_port = embedded_listener
        .local_addr()
        .expect("embedded SSH address")
        .port();
    let (embedded_shutdown, embedded_shutdown_rx) = oneshot::channel();
    let embedded_task = tokio::spawn(crate::embedded_ssh::serve_until(
        embedded_listener,
        crate::embedded_ssh::EmbeddedSshConfig::new(
            "managed-user",
            host_key_path,
            authorized_keys_path,
        ),
        async move {
            let _ = embedded_shutdown_rx.await;
        },
    ));

    let mut tunnel = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        embedded_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("reverse tunnel to embedded SSH");
    fixture.wait_forward_requested().await;

    let forwarded = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((fixture.gateway_host.as_str(), fixture.remote_port)),
    )
    .await
    .expect("reverse forwarded connection deadline")
    .expect("connect through test gateway reverse forward");
    let mut ssh = client::connect_stream(
        Arc::new(client::Config::default()),
        forwarded,
        StrictEmbeddedHost {
            expected: host_key.public_key().clone(),
        },
    )
    .await
    .expect("SSH over reverse forward");
    assert!(
        ssh.authenticate_publickey(
            "managed-user",
            PrivateKeyWithHashAlg::new(Arc::clone(&controller_key), None),
        )
        .await
        .expect("embedded SSH authentication")
        .success(),
        "enrolled controller key authenticates through reverse forward"
    );

    let second_forwarded = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((fixture.gateway_host.as_str(), fixture.remote_port)),
    )
    .await
    .expect("second reverse forwarded connection deadline")
    .expect("open second forwarded channel through test gateway");
    let mut second_ssh = client::connect_stream(
        Arc::new(client::Config::default()),
        second_forwarded,
        StrictEmbeddedHost {
            expected: host_key.public_key().clone(),
        },
    )
    .await
    .expect("second SSH connection over reverse forward");
    assert!(
        second_ssh
            .authenticate_publickey(
                "managed-user",
                PrivateKeyWithHashAlg::new(Arc::clone(&controller_key), None),
            )
            .await
            .expect("second embedded SSH authentication")
            .success(),
        "controller key authenticates on concurrent reverse channel"
    );

    let large_sftp = open_reverse_test_sftp(&ssh).await;
    let concurrent_sftp = open_reverse_test_sftp(&second_ssh).await;
    let payload = (0..4 * 1024 * 1024)
        .map(|index| ((index * 37 + index / 251) & 0xff) as u8)
        .collect::<Vec<_>>();
    let large_path = dir
        .path()
        .join("large-payload.bin")
        .to_string_lossy()
        .into_owned();
    let concurrent_path = dir
        .path()
        .join("concurrent-channel.bin")
        .to_string_lossy()
        .into_owned();
    let concurrent_marker = b"concurrent-sftp-channel-progress";
    tokio::time::timeout(Duration::from_secs(30), async {
        let large_transfer = async {
            let mut remote = large_sftp
                .open_with_flags(
                    large_path.clone(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .expect("create large SFTP file");
            remote
                .write_all(&payload)
                .await
                .expect("upload 4 MiB over reverse SFTP");
            remote.close().await.expect("close large upload");
        };
        let concurrent_transfer = async {
            let mut remote = concurrent_sftp
                .open_with_flags(
                    concurrent_path.clone(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .expect("create concurrent SFTP file");
            remote
                .write_all(concurrent_marker)
                .await
                .expect("concurrent SFTP channel write");
            remote.close().await.expect("close concurrent SFTP write");
            let mut remote = concurrent_sftp
                .open(concurrent_path.clone())
                .await
                .expect("open concurrent SFTP file for read");
            let mut restored = Vec::new();
            remote
                .read_to_end(&mut restored)
                .await
                .expect("concurrent SFTP channel read");
            remote.close().await.expect("close concurrent SFTP read");
            assert_eq!(
                restored, concurrent_marker,
                "concurrent channel completes exactly"
            );
        };
        tokio::join!(large_transfer, concurrent_transfer);
    })
    .await
    .expect("concurrent reverse SFTP transfer deadline");

    let metadata = large_sftp
        .metadata(large_path.clone())
        .await
        .expect("large remote metadata");
    assert_eq!(metadata.size, Some(4 * 1024 * 1024));
    let mut remote = large_sftp
        .open(large_path)
        .await
        .expect("open large remote file for exact-byte verification");
    let mut restored = Vec::new();
    remote
        .read_to_end(&mut restored)
        .await
        .expect("download large reverse SFTP file");
    remote.close().await.expect("close large download");
    assert_eq!(
        restored, payload,
        "reverse SFTP preserves every payload byte"
    );

    large_sftp.close().await.expect("close large SFTP session");
    concurrent_sftp
        .close()
        .await
        .expect("close concurrent SFTP session");
    ssh.disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect embedded SSH client");
    second_ssh
        .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect second embedded SSH client");
    tunnel.shutdown().await.expect("reverse tunnel shutdown");
    embedded_shutdown
        .send(())
        .expect("embedded SSH server still running");
    tokio::time::timeout(Duration::from_secs(6), embedded_task)
        .await
        .expect("embedded SSH shutdown deadline")
        .expect("embedded SSH server task")
        .expect("embedded SSH server shutdown");
    fixture.abort_server();
}

#[derive(Clone)]
struct StrictEmbeddedHost {
    expected: russh::keys::ssh_key::PublicKey,
}

impl client::Handler for StrictEmbeddedHost {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(server_public_key.certificate().is_none()
            && server_public_key.public_key().key_data() == self.expected.key_data())
    }
}

async fn open_reverse_test_sftp(session: &client::Handle<StrictEmbeddedHost>) -> SftpSession {
    let mut channel = session
        .channel_open_session()
        .await
        .expect("open SFTP SSH channel");
    channel
        .request_subsystem(true, "sftp")
        .await
        .expect("request SFTP subsystem");
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Success) => break,
            Some(russh::ChannelMsg::Failure) => panic!("embedded SFTP subsystem rejected"),
            Some(_) => {}
            None => panic!("SFTP channel closed before acknowledgement"),
        }
    }
    SftpSession::new(channel.into_stream())
        .await
        .expect("initialize reverse SFTP session")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_second_gateway_host_key_fails_closed_without_affecting_first() {
    let (first_fixture, second_fixture, config) = active_active_fixture().await;
    let wrong_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong host key");
    fs::write(
        config.known_hosts.as_ref().expect("known_hosts"),
        format!(
            "[{}]:{} {}\n[{}]:{} {}\n",
            first_fixture.gateway_host,
            first_fixture.ssh_address.port(),
            first_fixture.host_public_key,
            second_fixture.gateway_host,
            second_fixture.ssh_address.port(),
            wrong_key.public_key().to_openssh().expect("wrong key line"),
        ),
    )
    .expect("write wrong second pin");
    let error = ReverseTunnel::connect(
        &config,
        &config.gateways[1],
        27_391,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .err()
    .expect("wrong gateway pin must fail closed");
    assert!(error.to_string().contains("SSH transport") || error.to_string().contains("key"));
    first_fixture.abort_server();
    second_fixture.abort_server();
}

#[test]
fn tls_proxy_command_preserves_exact_raw_stream_argv() {
    let config = SshTunnelConfig {
        program: Some(PathBuf::from("legacy-ssh.exe")),
        gateways: vec![SshGatewayEndpoint {
            host: "gateway.example.test".to_owned(),
            user: "agent".to_owned(),
            port: 443,
            tls_proxy: None,
        }],
        remote_port: 41_001,
        identity: Some(PathBuf::from("id_ed25519")),
        known_hosts: Some(PathBuf::from("known_hosts")),
        reconnect_seconds: 1,
    };
    let proxy = SshTlsProxyConfig {
        program: PathBuf::from("openssl.exe"),
        server_name: "edge.example.test".to_owned(),
        alpn: Some("http/1.1".to_owned()),
    };

    let command = super::proxy::tls_proxy_command(&config.gateways[0], &proxy);
    assert_eq!(command.get_program(), proxy.program.as_os_str());
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        vec![
            "s_client",
            "-quiet",
            "-connect",
            "gateway.example.test:443",
            "-servername",
            "edge.example.test",
            "-alpn",
            "http/1.1",
        ]
    );
    assert!(
        args.iter().all(|arg| !arg.contains("ssh.exe")),
        "TLS helper command must not delegate to an external SSH client"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_shutdown_reaps_owned_tls_proxy_process() {
    use std::os::unix::fs::PermissionsExt;

    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let fixture = start_gateway(&client_key, &host_key).await;
    let (local_port, echo_task) = echo_listener().await;
    let proxy_script = fixture._dir.path().join("raw-proxy");
    let proxy_pid = fixture._dir.path().join("raw-proxy.pid");
    let descendant_pid = fixture._dir.path().join("raw-proxy-descendant.pid");
    fs::write(
        &proxy_script,
        format!(
            "#!/bin/bash\nset -eu\nprintf '%s\\n' $$ > '{}'\n(sleep 300) &\nprintf '%s\\n' $! > '{}'\nexec 3<>/dev/tcp/127.0.0.1/{}\ncat <&0 >&3 &\nup=$!\ncat <&3 >&1 &\ndown=$!\nwait $up $down\n",
            proxy_pid.display(),
            descendant_pid.display(),
            fixture.ssh_address.port()
        ),
    )
    .expect("proxy script");
    let mut permissions = fs::metadata(&proxy_script)
        .expect("proxy metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&proxy_script, permissions).expect("proxy chmod");

    let mut config = tunnel_config(&fixture);
    config.gateways[0].tls_proxy = Some(SshTlsProxyConfig {
        program: proxy_script,
        server_name: "edge.example.test".to_owned(),
        alpn: Some("http/1.1".to_owned()),
    });
    let mut tunnel = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("proxied reverse tunnel");
    let mut remote = tokio::net::TcpStream::connect(("127.0.0.1", fixture.remote_port))
        .await
        .expect("remote forwarded connection through TLS proxy");
    let raw_bytes = [0, 0xff, b'\r', b'\n', b'\0', 0x80, 0x01];
    remote.write_all(&raw_bytes).await.expect("write raw bytes");
    let mut response = vec![0; raw_bytes.len()];
    remote
        .read_exact(&mut response)
        .await
        .expect("read raw bytes");
    assert_eq!(
        response, raw_bytes,
        "proxy transport must preserve raw bytes"
    );
    let pid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(text) = fs::read_to_string(&proxy_pid)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy pid publication");
    let descendant = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(text) = fs::read_to_string(&descendant_pid)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy descendant pid publication");

    tunnel.shutdown().await.expect("tunnel shutdown");
    for (label, pid) in [("TLS proxy", pid), ("TLS proxy descendant", descendant)] {
        // SAFETY: signal 0 only probes whether the recorded process PID is still live.
        let probe = unsafe { libc::kill(pid, 0) };
        if probe == -1 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH),
                "{label} must be gone before shutdown returns"
            );
            continue;
        }

        // Linux process-group teardown has killed the grandchild, but an unreaped orphan
        // can temporarily remain as a zombie under its new parent. kill(pid, 0) reports
        // zombies as existing; that is not a running process. Do not permit any live state,
        // including sleeping, stopped, uninterruptible, or an unreadable /proc entry.
        #[cfg(target_os = "linux")]
        if label == "TLS proxy descendant" {
            match fs::read_to_string(format!("/proc/{pid}/status")) {
                // The process can disappear between kill(pid, 0) and the /proc read.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(status) => assert!(
                    linux_proc_status_is_zombie(&status),
                    "{label} must have exited before shutdown returns; status: {status}"
                ),
                Err(error) => panic!("cannot inspect {label} after shutdown: {error}"),
            }
            continue;
        }
        panic!("{label} must be gone before shutdown returns");
    }
    echo_task.abort();
    fixture.abort_server();
}

#[cfg(target_os = "linux")]
fn linux_proc_status_is_zombie(status: &str) -> bool {
    status
        .lines()
        .filter_map(|line| line.strip_prefix("State:"))
        .any(|value| value.split_whitespace().next() == Some("Z"))
}

#[cfg(target_os = "linux")]
#[test]
fn tls_proxy_shutdown_considers_only_a_confirmed_zombie_to_be_exited() {
    assert!(linux_proc_status_is_zombie(
        "Name:\tsleep\nState:\tZ (zombie)\n"
    ));
    for status in [
        "Name:\tsleep\nState:\tS (sleeping)\n",
        "Name:\tsleep\nState:\tR (running)\n",
        "Name:\tsleep\nState:\tD (disk sleep)\n",
        "Name:\tsleep\nState:\tT (stopped)\n",
        "Name:\tsleep\n",
        "State:\tInvalid\n",
    ] {
        assert!(!linux_proc_status_is_zombie(status));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn tls_proxy_early_exit_closes_the_raw_stdout_stream() {
    use std::os::unix::fs::PermissionsExt;

    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let fixture = start_gateway(&client_key, &host_key).await;
    let proxy_script = fixture._dir.path().join("early-exit-proxy");
    fs::write(
        &proxy_script,
        "#!/bin/sh\nprintf 'proxy diagnostic\\n' >&2\nexit 23\n",
    )
    .expect("proxy script");
    let mut permissions = fs::metadata(&proxy_script)
        .expect("proxy metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&proxy_script, permissions).expect("proxy chmod");
    let mut config = tunnel_config(&fixture);
    config.gateways[0].tls_proxy = Some(SshTlsProxyConfig {
        program: proxy_script,
        server_name: "edge.example.test".to_owned(),
        alpn: None,
    });

    let (mut stream, process) = super::proxy::spawn_tls_proxy(
        &config.gateways[0],
        config.gateways[0]
            .tls_proxy
            .as_ref()
            .expect("TLS proxy config"),
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("spawn TLS proxy");
    let mut bytes = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes))
        .await
        .expect("stdout EOF after early exit")
        .expect("stdout read");
    assert_eq!(read, 0, "early process exit must close the live raw stream");
    let mut owner = Some(process);
    super::proxy::stop_proxy_process(&mut owner)
        .await
        .expect("confirmed early-exit process-tree shutdown");
    assert!(owner.is_none());
    fixture.abort_server();
}

#[test]
fn tls_proxy_process_owner_has_no_legacy_async_owned_process() {
    let source = include_str!("client.rs");
    assert!(!source.contains(concat!("Async", "OwnedProcess")));
}

#[tokio::test]
async fn tls_proxy_raw_stdout_sink_surfaces_closed_reader_errors() {
    let (reader, writer) = tokio::io::duplex(1);
    drop(reader);
    let mut sink = ProxyStdoutSink::new(Arc::new(tokio::sync::Mutex::new(writer)));
    let error = sink
        .write_chunk(b"raw")
        .await
        .expect_err("closed russh stream must fail the ProcessKit raw sink");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn russh_reverse_forward_round_trips_and_shuts_down() {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let fixture = start_gateway(&client_key, &host_key).await;
    let (local_port, echo_task) = echo_listener().await;
    let config = tunnel_config(&fixture);

    let mut tunnel = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("reverse tunnel");

    let mut remote = tokio::net::TcpStream::connect(("127.0.0.1", fixture.remote_port))
        .await
        .expect("remote forwarded connection");
    remote.write_all(b"round-trip").await.expect("write");
    let mut response = vec![0; 10];
    remote.read_exact(&mut response).await.expect("read");
    assert_eq!(&response, b"round-trip");

    tunnel.shutdown().await.expect("tunnel shutdown");
    echo_task.await.expect("echo task");
    fixture.server_task.abort();
}

#[derive(Clone)]
struct ReconnectGateway {
    client_key: russh::keys::PublicKey,
    attempts: Arc<AtomicUsize>,
    remote_port: u16,
}

struct ReconnectGatewaySession {
    client_key: russh::keys::PublicKey,
    attempts: Arc<AtomicUsize>,
    remote_port: u16,
}

impl server::Server for ReconnectGateway {
    type Handler = ReconnectGatewaySession;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        ReconnectGatewaySession {
            client_key: self.client_key.clone(),
            attempts: Arc::clone(&self.attempts),
            remote_port: self.remote_port,
        }
    }
}

impl server::Handler for ReconnectGatewaySession {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if public_key.key_data() == self.client_key.key_data() {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if address != "127.0.0.1" || *port != u32::from(self.remote_port) {
            return Ok(false);
        }
        let attempt = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if attempt == 1 {
            let handle = session.handle();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = handle
                    .disconnect(
                        Disconnect::ByApplication,
                        "test transient disconnect".to_owned(),
                        "en".to_owned(),
                    )
                    .await;
            });
        }
        Ok(true)
    }
}

async fn start_reconnect_gateway(
    client_key: &PrivateKey,
    host_key: &PrivateKey,
) -> (GatewayFixture, Arc<AtomicUsize>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("client key encoding"),
    )
    .expect("identity");
    hostlink_core::restrict_private_file(&identity).expect("private identity");

    let ssh_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("SSH listener");
    let ssh_address = ssh_listener.local_addr().expect("SSH address");
    let known_hosts = dir.path().join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            ssh_address.port(),
            host_key.public_key().to_openssh().expect("host public key")
        ),
    )
    .expect("known hosts");

    let remote_port = 41001;
    let attempts = Arc::new(AtomicUsize::new(0));
    let config = Arc::new(server::Config {
        keys: vec![host_key.clone()],
        nodelay: true,
        ..Default::default()
    });
    let mut server = ReconnectGateway {
        client_key: client_key.public_key().clone(),
        attempts: Arc::clone(&attempts),
        remote_port,
    };
    let server_task =
        tokio::spawn(async move { server.run_on_socket(config, &ssh_listener).await });

    (
        GatewayFixture {
            _dir: dir,
            gateway_host: ssh_address.ip().to_string(),
            host_public_key: host_key
                .public_key()
                .to_openssh()
                .expect("host public key")
                .to_owned(),
            ssh_address,
            remote_port,
            identity,
            known_hosts,
            forward_listener: Arc::new(Mutex::new(None)),
            server_task,
        },
        attempts,
    )
}

pub(crate) async fn reconnect_fixture() -> (GatewayFixture, SshTunnelConfig, Arc<AtomicUsize>) {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let (fixture, attempts) = start_reconnect_gateway(&client_key, &host_key).await;
    let config = tunnel_config(&fixture);
    (fixture, config, attempts)
}

#[derive(Clone, Copy)]
enum ForwardProbeMode {
    Exact,
    WrongAddress,
    WrongPort,
}

#[derive(Clone)]
struct ForwardProbeGateway {
    client_key: russh::keys::PublicKey,
    remote_port: u16,
    mode: ForwardProbeMode,
    result: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
}

struct ForwardProbeSession {
    client_key: russh::keys::PublicKey,
    remote_port: u16,
    mode: ForwardProbeMode,
    result: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
}

impl server::Server for ForwardProbeGateway {
    type Handler = ForwardProbeSession;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        ForwardProbeSession {
            client_key: self.client_key.clone(),
            remote_port: self.remote_port,
            mode: self.mode,
            result: Arc::clone(&self.result),
        }
    }
}

impl server::Handler for ForwardProbeSession {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if public_key.key_data() == self.client_key.key_data() {
            Auth::Accept
        } else {
            Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if address != "127.0.0.1" || *port != u32::from(self.remote_port) {
            return Ok(false);
        }
        let (connected_address, connected_port) = match self.mode {
            ForwardProbeMode::Exact => ("127.0.0.1".to_owned(), u32::from(self.remote_port)),
            ForwardProbeMode::WrongAddress => ("0.0.0.0".to_owned(), u32::from(self.remote_port)),
            ForwardProbeMode::WrongPort => {
                ("127.0.0.1".to_owned(), u32::from(self.remote_port) + 1)
            }
        };
        let result = self.result.lock().await.take();
        let handle = session.handle();
        tokio::spawn(async move {
            let rejected = handle
                .channel_open_forwarded_tcpip(
                    connected_address,
                    connected_port,
                    "127.0.0.1",
                    50_000,
                )
                .await
                .is_err();
            if let Some(result) = result {
                let _ = result.send(rejected);
            }
        });
        Ok(true)
    }
}

async fn start_forward_probe_gateway(
    client_key: &PrivateKey,
    host_key: &PrivateKey,
    mode: ForwardProbeMode,
) -> (GatewayFixture, oneshot::Receiver<bool>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = dir.path().join("id_ed25519");
    fs::write(
        &identity,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("client key encoding"),
    )
    .expect("identity");
    hostlink_core::restrict_private_file(&identity).expect("private identity");

    let ssh_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("SSH listener");
    let ssh_address = ssh_listener.local_addr().expect("SSH address");
    let known_hosts = dir.path().join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            ssh_address.port(),
            host_key.public_key().to_openssh().expect("host public key")
        ),
    )
    .expect("known hosts");

    let remote_port = 41_002;
    let (result_tx, result_rx) = oneshot::channel();
    let config = Arc::new(server::Config {
        keys: vec![host_key.clone()],
        nodelay: true,
        ..Default::default()
    });
    let mut server = ForwardProbeGateway {
        client_key: client_key.public_key().clone(),
        remote_port,
        mode,
        result: Arc::new(Mutex::new(Some(result_tx))),
    };
    let server_task =
        tokio::spawn(async move { server.run_on_socket(config, &ssh_listener).await });

    (
        GatewayFixture {
            _dir: dir,
            gateway_host: ssh_address.ip().to_string(),
            host_public_key: host_key
                .public_key()
                .to_openssh()
                .expect("host public key")
                .to_owned(),
            ssh_address,
            remote_port,
            identity,
            known_hosts,
            forward_listener: Arc::new(Mutex::new(None)),
            server_task,
        },
        result_rx,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn russh_reverse_tunnel_reconnects_after_transient_disconnect() {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let (fixture, attempts) = start_reconnect_gateway(&client_key, &host_key).await;
    let config = tunnel_config(&fixture);

    let mut first = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        27391,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("first reverse tunnel");
    let _first_result = tokio::time::timeout(Duration::from_secs(2), first.wait())
        .await
        .expect("transient disconnect must end the first session");

    let mut second = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        27391,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("reconnected reverse tunnel");
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "second connection must re-establish the reverse forward"
    );
    second.shutdown().await.expect("second tunnel shutdown");
    fixture.server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn russh_reverse_tunnel_rejects_wrong_host_key_and_client_key() {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let wrong_client =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong client");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let wrong_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong host");
    let fixture = start_gateway(&client_key, &host_key).await;
    let (local_port, echo_task) = echo_listener().await;

    let mut wrong_host_config = tunnel_config(&fixture);
    fs::write(
        &fixture.known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            fixture.ssh_address.port(),
            wrong_host
                .public_key()
                .to_openssh()
                .expect("wrong host public key")
        ),
    )
    .expect("wrong known hosts");
    let host_error = ReverseTunnel::connect(
        &wrong_host_config,
        &wrong_host_config.gateways[0],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .err()
    .expect("wrong host key must fail");
    assert!(
        host_error.to_string().contains("SSH transport") || host_error.to_string().contains("key")
    );

    fs::write(
        &fixture.known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            fixture.ssh_address.port(),
            host_key.public_key().to_openssh().expect("host public key")
        ),
    )
    .expect("known hosts");
    fs::write(
        &fixture.identity,
        wrong_client
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("wrong client encoding"),
    )
    .expect("wrong identity");
    hostlink_core::restrict_private_file(&fixture.identity).expect("private wrong identity");
    wrong_host_config.identity = Some(fixture.identity.clone());
    let auth_error = ReverseTunnel::connect(
        &wrong_host_config,
        &wrong_host_config.gateways[0],
        local_port,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .err()
    .expect("wrong client key must fail");
    assert_eq!(auth_error.kind(), io::ErrorKind::PermissionDenied);

    echo_task.abort();
    fixture.server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarded_channel_is_rejected_when_local_target_is_unavailable() {
    let client_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
    let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let (fixture, rejected) =
        start_forward_probe_gateway(&client_key, &host_key, ForwardProbeMode::Exact).await;
    let config = tunnel_config(&fixture);
    let mut tunnel = ReverseTunnel::connect(
        &config,
        &config.gateways[0],
        // Port zero is never a connectable TCP destination. This exercises the
        // fail-closed channel-open path without a reserve/drop/rebind race.
        0,
        &AgentEnvironmentPolicy::default(),
    )
    .await
    .expect("reverse tunnel");

    assert!(
        tokio::time::timeout(Duration::from_secs(2), rejected)
            .await
            .expect("forward rejection deadline")
            .expect("forward rejection result"),
        "gateway must receive channel-open failure before a missing local target is accepted"
    );
    tunnel.shutdown().await.expect("tunnel shutdown");
    fixture.abort_server();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarded_channel_is_rejected_for_wrong_bound_address_or_port() {
    for mode in [ForwardProbeMode::WrongAddress, ForwardProbeMode::WrongPort] {
        let client_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("client key");
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let (fixture, rejected) = start_forward_probe_gateway(&client_key, &host_key, mode).await;
        let config = tunnel_config(&fixture);
        let mut tunnel = ReverseTunnel::connect(
            &config,
            &config.gateways[0],
            27_391,
            &AgentEnvironmentPolicy::default(),
        )
        .await
        .expect("reverse tunnel");

        assert!(
            tokio::time::timeout(Duration::from_secs(2), rejected)
                .await
                .expect("bound-destination rejection deadline")
                .expect("bound-destination rejection result"),
            "gateway must receive channel-open failure for a destination outside the exact bound loopback forward"
        );
        tunnel.shutdown().await.expect("tunnel shutdown");
        fixture.abort_server();
    }
}
