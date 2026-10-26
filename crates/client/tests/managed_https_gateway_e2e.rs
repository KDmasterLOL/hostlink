#![cfg(unix)]

//! Opt-in process-level acceptance for the real Hub, HTTPS proxy, OpenSSH gateway,
//! enrollment Agent, and pinned russh Controller path. Run via the fixture script.

use hostlink::{
    connect::HostConnection,
    forward,
    hub::{HubClient, HubConfig},
    run::{JobSpec, JobStateKind, JobStream, Output, Start, Status},
};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Children {
    children: Vec<Child>,
    stopped: bool,
}

impl Children {
    fn start(&mut self, mut command: Command) -> &mut Child {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let child = command
            .spawn()
            .expect("start private fixture child process");
        self.children.push(child);
        self.children.last_mut().expect("just inserted child")
    }

    fn stop_all(&mut self) -> bool {
        if self.stopped {
            return true;
        }
        let mut clean = true;
        for child in &mut self.children {
            // SAFETY: every process is started in a fresh, fixture-owned process group.
            // The negative PID targets only that child and its descendants.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGTERM);
            }
        }
        for child in &mut self.children {
            let process_group = -(child.id() as i32);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut group_exists = true;
            while Instant::now() < deadline {
                let _ = child.try_wait();
                // SAFETY: the child owns a fresh process group; signal 0 only probes it.
                group_exists = unsafe { libc::kill(process_group, 0) } == 0;
                if !group_exists {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            // A descendant may have survived SIGTERM after the group leader exited.
            // Escalate against the whole private process group, never just the leader.
            // SAFETY: this targets only the fresh group created for this fixture child.
            if group_exists {
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
                let reap_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let _ = child.try_wait();
                    // SAFETY: signal 0 probes only this fixture-owned process group.
                    group_exists = unsafe { libc::kill(process_group, 0) } == 0;
                    if !group_exists || Instant::now() >= reap_deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                clean &= !group_exists;
            }
            let _ = child.wait();
        }
        self.stopped = true;
        clean
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        let _ = self.stop_all();
    }
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("set private mode");
}

fn private_write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("write private fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set private mode");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

fn wait_port(address: SocketAddr, mut child: Option<&mut Child>) {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return;
        }
        if let Some(child) = child.as_deref_mut()
            && let Some(status) = child.try_wait().expect("inspect fixture process")
        {
            panic!("fixture child exited before binding (status {status})");
        }
        assert!(
            Instant::now() < end,
            "loopback fixture did not become ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("generate disposable key")
}

fn private_key_file(path: &Path, key: &PrivateKey) {
    private_write(path, key.to_openssh(LineEnding::LF).expect("serialize key"));
}

fn public_key(key: &PrivateKey) -> String {
    key.public_key().to_openssh().expect("serialize public key")
}

fn ssh_fingerprint(public_key_file: &Path) -> String {
    let output = run_ok(
        Command::new("ssh-keygen")
            .args(["-lf"])
            .arg(public_key_file)
            .args(["-E", "sha256"]),
        "compute disposable SSH key fingerprint",
    );
    String::from_utf8(output.stdout)
        .expect("ssh-keygen fingerprint is UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("ssh-keygen emitted fingerprint")
        .to_owned()
}

fn run_ok(command: &mut Command, what: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|_| panic!("run {what}"));
    assert!(
        output.status.success(),
        "{what} failed with status {}",
        output.status
    );
    output
}

fn write_server_certificate(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ca_key = root.join("fixture-ca.key");
    let ca_cert = root.join("fixture-ca.pem");
    let leaf_key = root.join("tls.key");
    let leaf_csr = root.join("tls.csr");
    let leaf_cert = root.join("tls.pem");
    let ext = root.join("tls.ext");
    run_ok(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=fixture-ca",
                "-keyout",
            ])
            .arg(&ca_key)
            .arg("-out")
            .arg(&ca_cert),
        "generate disposable TLS CA",
    );
    run_ok(
        Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
            ])
            .arg(&leaf_key)
            .arg("-out")
            .arg(&leaf_csr),
        "generate disposable TLS leaf",
    );
    private_write(
        &ext,
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
    );
    run_ok(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "2", "-CAcreateserial", "-CA"])
            .arg(&ca_cert)
            .arg("-CAkey")
            .arg(&ca_key)
            .arg("-in")
            .arg(&leaf_csr)
            .arg("-out")
            .arg(&leaf_cert)
            .arg("-extfile")
            .arg(&ext),
        "sign disposable TLS leaf",
    );
    run_ok(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=wrong-fixture-ca",
                "-keyout",
            ])
            .arg(root.join("wrong-ca.key"))
            .arg("-out")
            .arg(root.join("wrong-ca.pem")),
        "generate unrelated TLS CA",
    );
    (ca_cert, leaf_cert, leaf_key)
}

fn private_log(path: &Path) -> Stdio {
    Stdio::from(fs::File::create(path).expect("create private process log"))
}

fn hub_config(
    root: &Path,
    listen: SocketAddr,
    tls_url: &str,
    ssh_port: u16,
    reverse_port: u16,
    ssh_key: &str,
    operator_key: &str,
) -> PathBuf {
    let path = root.join("hub.json");
    let value = serde_json::json!({
        "version": 2,
        "listen": listen.to_string(),
        "public_url": tls_url,
        "state_root": root.join("hostlink-hub-v2"),
        "authorized_keys": root.join("gateway/hostlink-v2-authorized_keys"),
        "gateways": [{
            "host": "127.0.0.1", "user": std::env::var("USER").unwrap(),
            "port": ssh_port, "host_public_key": ssh_key
        }],
        "operator_ssh_public_keys": [operator_key],
        "port_from": reverse_port,
        "port_to": reverse_port,
        "reserved_ports": []
    });
    private_write(&path, serde_json::to_vec_pretty(&value).unwrap());
    path
}

fn write_caddyfile(path: &Path, url_port: u16, cert: &Path, key: &Path, hub: SocketAddr) {
    let content = format!(
        "{{\n  admin off\n  auto_https off\n}}\nhttps://localhost:{url_port} {{\n  bind 127.0.0.1\n  tls {} {}\n  reverse_proxy http://{}\n}}\n",
        cert.display(),
        key.display(),
        hub
    );
    private_write(path, content);
}

fn cli_env(command: &mut Command, config: &Path) {
    command.env("HOSTLINK_HUB_CONFIG", config);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires openssh-server, Caddy, OpenSSL, and the fixture script"]
async fn actual_https_hub_enrollment_openssh_projection_and_managed_russh_flow() {
    let agent_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_AGENT_BIN").expect("fixture script sets HOSTLINK_AGENT_BIN"),
    );
    let hub_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_HUB_BIN").expect("fixture script sets HOSTLINK_HUB_BIN"),
    );
    let client_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_CLIENT_BIN").expect("fixture script sets HOSTLINK_CLIENT_BIN"),
    );
    let root = tempfile::tempdir().expect("disposable HOME fixture");
    private_dir(root.path());
    let gateway_root = root.path().join("gateway");
    private_dir(&gateway_root);
    let mut children = Children {
        children: Vec::new(),
        stopped: false,
    };
    let old_ssh_pids = Command::new("pgrep")
        .args(["-x", "sshd"])
        .output()
        .expect("snapshot pre-existing sshd process IDs")
        .stdout;
    let old_ssh_port = Command::new("ss")
        .args(["-ltn", "sport", "=", ":22"])
        .output()
        .expect("snapshot pre-existing port 22 listeners")
        .stdout;

    let operator = key();
    let sshd_host = root.path().join("sshd_host_key");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&sshd_host),
        "generate isolated sshd host key",
    );
    let sshd_host_public =
        fs::read_to_string(format!("{}.pub", sshd_host.display())).expect("read sshd host pin");
    let controller_key = root.path().join("controller_key");
    private_key_file(&controller_key, &operator);
    let operator_authorized = root.path().join("controller_authorized_keys");
    private_write(
        &operator_authorized,
        format!("{} hostlink-fixture-controller\n", public_key(&operator)),
    );
    let ssh_port = free_port();
    let test_gateway_known_hosts = root.path().join("gateway-known-hosts");
    private_write(
        &test_gateway_known_hosts,
        format!("[127.0.0.1]:{ssh_port} {}", sshd_host_public.trim()),
    );
    let sshd_config = root.path().join("sshd_config");
    private_write(
        &sshd_config,
        format!(
            "Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {} {}\nStrictModes no\nAllowUsers {}\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowTcpForwarding yes\nGatewayPorts no\nX11Forwarding no\nPermitUserEnvironment no\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n",
            sshd_host.display(),
            root.path().join("sshd.pid").display(),
            operator_authorized.display(),
            gateway_root.join("hostlink-v2-authorized_keys").display(),
            std::env::var("USER").unwrap()
        ),
    );
    let sshd_bin = std::env::var_os("HOSTLINK_SSHD_BIN").unwrap_or_else(|| "/usr/sbin/sshd".into());
    let caddy_bin =
        std::env::var_os("HOSTLINK_CADDY_BIN").unwrap_or_else(|| "/usr/bin/caddy".into());
    run_ok(
        Command::new(&sshd_bin).args(["-t", "-f"]).arg(&sshd_config),
        "validate isolated sshd config",
    );
    let mut sshd = Command::new(&sshd_bin);
    sshd.args(["-D", "-e", "-f"])
        .arg(&sshd_config)
        .stdout(private_log(&root.path().join("sshd.stdout.log")))
        .stderr(private_log(&root.path().join("sshd.stderr.log")));
    let sshd_child = children.start(sshd);
    wait_port(
        SocketAddr::from(([127, 0, 0, 1], ssh_port)),
        Some(sshd_child),
    );

    // The v2 projection path is passed directly to this test sshd. It is never copied
    // into ~/.ssh or a system authorized_keys file.
    let hub_listener = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let tls_port = free_port();
    let tls_url = format!("https://localhost:{tls_port}");
    let (ca_cert, leaf_cert, leaf_key) = write_server_certificate(root.path());
    let tls_config = root.path().join("Caddyfile");
    write_caddyfile(&tls_config, tls_port, &leaf_cert, &leaf_key, hub_listener);
    let sshd_key_line = sshd_host_public.trim();
    let operator_public = public_key(&operator);
    let reverse_port = free_port();
    let config_path = hub_config(
        root.path(),
        hub_listener,
        &tls_url,
        ssh_port,
        reverse_port,
        sshd_key_line,
        &operator_public,
    );
    let operator_token = format!("fixture-operator-{}", uuid::Uuid::new_v4().simple());
    let gateway_token = format!("fixture-gateway-{}", uuid::Uuid::new_v4().simple());
    let mut hub = Command::new(&hub_bin);
    hub.args(["serve", "--config"])
        .arg(&config_path)
        .env("HOSTLINK_HUB_OPERATOR_TOKEN", &operator_token)
        .env("HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN", &gateway_token)
        .stdout(private_log(&root.path().join("hub.stdout.log")))
        .stderr(private_log(&root.path().join("hub.stderr.log")));
    let hub_child = children.start(hub);
    wait_port(hub_listener, Some(hub_child));
    let mut caddy = Command::new(&caddy_bin);
    private_dir(&root.path().join("caddy-home"));
    private_dir(&root.path().join("caddy-config"));
    private_dir(&root.path().join("caddy-data"));
    caddy
        .args(["run", "--config"])
        .arg(&tls_config)
        .args(["--adapter", "caddyfile"])
        .env("HOME", root.path().join("caddy-home"))
        .env("XDG_CONFIG_HOME", root.path().join("caddy-config"))
        .env("XDG_DATA_HOME", root.path().join("caddy-data"))
        .stdout(private_log(&root.path().join("caddy.stdout.log")))
        .stderr(private_log(&root.path().join("caddy.stderr.log")));
    let caddy_child = children.start(caddy);
    wait_port(
        SocketAddr::from(([127, 0, 0, 1], tls_port)),
        Some(caddy_child),
    );

    let token_file = root.path().join("operator.token");
    private_write(&token_file, operator_token);
    let controller_config = HubConfig {
        hub_url: tls_url.clone(),
        hub_ca_cert: Some(ca_cert.clone()),
        token_file: token_file.clone(),
        ssh_user: std::env::var("USER").unwrap(),
        identity: controller_key.clone(),
        gateway_identity: controller_key.clone(),
        preferred_gateway: None,
    };
    let hub_client =
        HubClient::from_config(&controller_config).expect("valid HTTPS with explicit local CA");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if hub_client.list_hosts().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("trusted HTTPS endpoint and child Hub become ready");

    // TLS remains fail-closed for both trust and hostname failures.
    let wrong_ca_config = HubConfig {
        hub_ca_cert: Some(root.path().join("wrong-ca.pem")),
        ..controller_config.clone()
    };
    assert!(
        HubClient::from_config(&wrong_ca_config)
            .unwrap()
            .list_hosts()
            .await
            .is_err(),
        "untrusted CA is rejected"
    );
    let wrong_host_config = HubConfig {
        hub_url: format!("https://127.0.0.1:{tls_port}"),
        ..controller_config.clone()
    };
    assert!(
        HubClient::from_config(&wrong_host_config)
            .unwrap()
            .list_hosts()
            .await
            .is_err(),
        "hostname mismatch is rejected"
    );

    // Agent's real enrollment executable first rejects bad CA and wrong-host pins.
    for (label, url, ca) in [
        (
            "wrong-ca",
            tls_url.clone(),
            root.path().join("wrong-ca.pem"),
        ),
        (
            "wrong-host",
            format!("https://127.0.0.1:{tls_port}"),
            ca_cert.clone(),
        ),
    ] {
        let invite = hub_client
            .invite(Some(format!("negative-{label}")), 300)
            .await
            .expect("create negative test invite");
        let negative_token = root.path().join(format!("{label}.token"));
        private_write(&negative_token, invite.token.expose_secret());
        let mut enroll = Command::new(&agent_bin);
        enroll
            .args(["enroll", "--hub-url", &url, "--hub-ca-cert"])
            .arg(ca)
            .args(["--token-file"])
            .arg(&negative_token)
            .args(["--root"])
            .arg(root.path().join(format!("{label}-agent")))
            .args(["--name", &format!("negative-{label}"), "--user"])
            .arg(std::env::var("USER").unwrap());
        assert!(
            !enroll
                .status()
                .expect("run negative Agent enrollment")
                .success(),
            "Agent must reject {label}"
        );
    }

    let invite = hub_client
        .invite(Some("managed-fixture".into()), 900)
        .await
        .expect("create one-use invite over HTTPS");
    let enrollment_token = root.path().join("enrollment.token");
    private_write(&enrollment_token, invite.token.expose_secret());
    let mut enroll = Command::new(&agent_bin);
    enroll
        .args(["enroll", "--hub-url", &tls_url, "--hub-ca-cert"])
        .arg(&ca_cert)
        .args(["--token-file"])
        .arg(&enrollment_token)
        .args(["--root"])
        .arg(root.path().join("agent-root"))
        .args(["--name", "managed-fixture", "--user"])
        .arg(std::env::var("USER").unwrap());
    run_ok(&mut enroll, "enroll actual Agent over trusted HTTPS");
    let agent_root = root.path().join("agent-root/state");
    let agent_config: serde_json::Value =
        serde_json::from_slice(&fs::read(agent_root.join("agent.json")).unwrap()).unwrap();
    let replay = Command::new(&agent_bin)
        .args(["enroll", "--hub-url", &tls_url, "--hub-ca-cert"])
        .arg(&ca_cert)
        .args(["--token-file"])
        .arg(&enrollment_token)
        .args(["--root"])
        .arg(root.path().join("agent-replay"))
        .args(["--name", "managed-fixture-replay", "--user"])
        .arg(std::env::var("USER").unwrap())
        .status()
        .expect("attempt one-use token replay");
    assert!(!replay.success(), "an enrollment invite is one-use");
    let agent_listen: SocketAddr = agent_config["listen"].as_str().unwrap().parse().unwrap();
    let mut agent_run = Command::new(&agent_bin);
    agent_run
        .args(["run", "--config"])
        .arg(agent_root.join("agent.json"))
        .stdout(private_log(&root.path().join("agent.stdout.log")))
        .stderr(private_log(&root.path().join("agent.stderr.log")));
    let agent_child = children.start(agent_run);
    wait_port(agent_listen, Some(agent_child));

    // Controller's normal config and CLI use the private CA field and name selector.
    let cli_config = root.path().join("controller-hub.json");
    private_write(
        &cli_config,
        serde_json::to_vec_pretty(&controller_config).unwrap(),
    );
    let mut list = Command::new(&client_bin);
    cli_env(&mut list, &cli_config);
    let listed = run_ok(list.args(["list"]), "Hub-backed name inventory");
    assert!(String::from_utf8_lossy(&listed.stdout).contains("managed-fixture"));
    let mut exec = Command::new(&client_bin);
    cli_env(&mut exec, &cli_config);
    let result = exec
        .args([
            "exec",
            "--host",
            "managed-fixture",
            "--command",
            "printf managed-ok; printf managed-error >&2; exit 7",
        ])
        .output()
        .expect("run name-selected nested SSH exec");
    assert_eq!(result.status.code(), Some(7));
    assert_eq!(result.stdout, b"managed-ok");
    assert_eq!(result.stderr, b"managed-error");

    let host = hub_client
        .resolve_host_spec("managed-fixture", &controller_config)
        .await
        .expect("resolve live name and pins");
    assert!(
        fs::read_to_string(gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains("permitlisten=\"127.0.0.1:"),
        "sshd reads the Hub-owned v2 projection file directly"
    );
    let machine: serde_json::Value =
        serde_json::from_slice(&fs::read(agent_root.join("machine.json")).unwrap()).unwrap();
    let enrolled_public = machine["ssh_public_key"].as_str().unwrap();
    assert!(
        fs::read_to_string(gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains(enrolled_public),
        "the exact enrolled reverse public key is projected for sshd"
    );
    let mut session = connect_retry(&host).await;
    let wrong = key();
    let wrong_identity = root.path().join("wrong-controller");
    private_key_file(&wrong_identity, &wrong);
    let mut wrong_route = host.clone();
    wrong_route.gateway.as_mut().unwrap().identity = wrong_identity;
    assert!(
        HostConnection::connect(&wrong_route).await.is_err(),
        "wrong SSH key is rejected by sshd"
    );
    let mut stale_pin = host.clone();
    stale_pin.host_public_key = public_key(&wrong);
    assert!(
        HostConnection::connect(&stale_pin).await.is_err(),
        "stale nested Agent host pin is rejected"
    );

    let artifact = b"managed-e2e-sftp\0\xff";
    let digest = Sha256::digest(artifact);
    let remote_name = format!(
        "{}.upload",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    session
        .sftp_upload(&remote_name, artifact)
        .await
        .expect("SFTP upload through OpenSSH gateway");
    assert_eq!(
        session
            .sftp_download(&remote_name)
            .await
            .expect("SFTP download through gateway"),
        artifact
    );

    // Durable JobStore only contains UUID-named job directories. Test-owned
    // executables live in a separate private sibling, not inside state/jobs.
    let program_root = agent_root.parent().unwrap().join("programs");
    private_dir(&program_root);
    let program = program_root.join("managed-job-shell");
    fs::copy("/bin/sh", &program).expect("stage private job executable");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
        .expect("lock staged executable");
    let job_id = uuid::Uuid::new_v4().to_string();
    let start = Start {
        id: job_id.clone(),
        spec: JobSpec {
            program: program.to_string_lossy().into_owned(),
            args: vec![
                "-c".into(),
                "sleep 1; printf job-out; printf job-err >&2; exit 7".into(),
            ],
            cwd: Some(program_root.to_string_lossy().into_owned()),
            source_sha256: format!("{:x}", Sha256::digest(fs::read(&program).unwrap())),
        },
    };
    session
        .job_start(&start)
        .await
        .expect("durable job accepted once");
    session
        .close()
        .await
        .expect("close first session before reattach");
    let mut resumed = connect_retry(&host).await;
    let status = Status { id: job_id.clone() };
    let terminal = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let result = resumed
                .job_status(&status)
                .await
                .expect("reattach by stable job id");
            if matches!(
                result.state.state,
                JobStateKind::Exited | JobStateKind::Failed
            ) {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("durable job terminal state");
    assert_eq!(terminal.state.code, Some(7));
    assert_eq!(
        resumed
            .job_output(&Output {
                id: job_id.clone(),
                stream: JobStream::Stdout,
                offset: 0
            })
            .await
            .unwrap()
            .data,
        b"job-out"
    );
    assert_eq!(
        resumed
            .job_output(&Output {
                id: job_id,
                stream: JobStream::Stderr,
                offset: 0
            })
            .await
            .unwrap()
            .data,
        b"job-err"
    );

    // A local loopback probe proves forward channels traverse sshd and the nested Agent.
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0; 256];
                while let Ok(n) = socket.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    if socket.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let forward = forward::start_local_forward(resumed, "127.0.0.1:0".parse().unwrap(), echo_addr)
        .await
        .expect("start loopback-only forwarding");
    let mut probe = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .unwrap();
    probe.write_all(b"tcp-probe").await.unwrap();
    let mut echoed = [0; 9];
    probe.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"tcp-probe");
    forward
        .shutdown()
        .await
        .expect("close loopback forward cleanly");
    echo_task.abort();

    // Wildcard reverse listening is denied by the projected permitlisten option.
    // Use a free port rather than the Agent's already occupied reverse port,
    // otherwise a simple port collision could masquerade as permitlisten.
    let reverse_port = free_port();
    let mut wildcard = Command::new("ssh")
        .args(["-F", "/dev/null", "-p", &ssh_port.to_string(), "-i"])
        .arg(agent_root.join("gateway_identity"))
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
        ])
        .arg(format!(
            "UserKnownHostsFile={}",
            test_gateway_known_hosts.display()
        ))
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N",
            "-R",
        ])
        .arg(format!("0.0.0.0:{reverse_port}:127.0.0.1:22"))
        .arg(format!("{}@127.0.0.1", std::env::var("USER").unwrap()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("attempt forbidden wildcard reverse listen");
    let wildcard_deadline = Instant::now() + Duration::from_secs(5);
    let wildcard_status = loop {
        if let Some(status) = wildcard.try_wait().expect("poll wildcard reverse attempt") {
            break Some(status);
        }
        if Instant::now() >= wildcard_deadline {
            let _ = wildcard.kill();
            let _ = wildcard.wait();
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        wildcard_status.is_some_and(|status| !status.success()),
        "gateway projection must deny wildcard reverse listener"
    );

    // One-use token replay and TLS failures are exercised above. The Hub's
    // clock/expiry policy is covered by its independent deterministic API
    // tests; do not sleep through a live 60-second token TTL in this fixture.

    // A second sshd process configured on the live gateway port must fail closed.
    let collision_config = root.path().join("sshd_collision_config");
    let collision_config_data = fs::read_to_string(&sshd_config)
        .unwrap()
        .replace("sshd.pid", "sshd-collision.pid");
    private_write(&collision_config, collision_config_data);
    let collision_log = root.path().join("sshd-collision.stderr.log");
    let mut collision = Command::new(&sshd_bin);
    collision
        .args(["-D", "-e", "-f"])
        .arg(&collision_config)
        .stdout(Stdio::null())
        .stderr(private_log(&collision_log));
    let mut collision = collision.spawn().expect("start collision probe");
    std::thread::sleep(Duration::from_millis(300));
    let collision_status = collision.try_wait().expect("poll collision probe");
    if collision_status.is_none() {
        let _ = collision.kill();
        let _ = collision.wait();
    }
    assert!(
        collision_status.is_some_and(|status| !status.success()),
        "port collision must prevent a second gateway from starting"
    );
    assert!(
        fs::read_to_string(collision_log)
            .unwrap_or_default()
            .contains("Address already in use"),
        "the second sshd must fail specifically because the selected loopback port is occupied"
    );

    // Revoke while an authenticated session remains: new managed resolution is denied,
    // existing session outcome is reported honestly and the live channel still works.
    let mut established = connect_retry(&host).await;
    let enrolled = hub_client.resolve_host("managed-fixture").await.unwrap();
    let receipt = hub_client
        .revoke(&enrolled)
        .await
        .expect("revoke over HTTPS");
    assert!(receipt.revoked_new_connections);
    assert!(!receipt.confirmed_session_terminated && !receipt.remote_uninstall);
    assert!(
        !fs::read_to_string(gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains("hostlink-agent:"),
        "revocation removes the Hub-owned SSH authorization projection"
    );
    assert!(
        hub_client
            .resolve_host_spec("managed-fixture", &controller_config)
            .await
            .is_err(),
        "new managed session is refused after revocation"
    );
    let mut revoked_cli = Command::new(&client_bin);
    cli_env(&mut revoked_cli, &cli_config);
    assert!(
        !revoked_cli
            .args([
                "exec",
                "--host",
                "managed-fixture",
                "--command",
                "printf should-not-run"
            ])
            .status()
            .expect("try fresh managed CLI session after revoke")
            .success(),
        "name-based CLI must refuse a new session after revocation"
    );
    assert_eq!(
        established
            .exec("printf existing-session", &[])
            .await
            .unwrap()
            .stdout,
        b"existing-session",
        "revoke does not claim to terminate an already established session"
    );
    established
        .close()
        .await
        .expect("close established session");
    let sshd_log = fs::read_to_string(root.path().join("sshd.stderr.log"))
        .expect("read private OpenSSH authorization log");
    let enrolled_public_file = root.path().join("enrolled_reverse.pub");
    private_write(&enrolled_public_file, format!("{enrolled_public}\n"));
    let agent_fingerprint = ssh_fingerprint(&enrolled_public_file);
    let controller_public_file = root.path().join("controller.pub");
    private_write(
        &controller_public_file,
        format!("{}\n", public_key(&operator)),
    );
    let controller_fingerprint = ssh_fingerprint(&controller_public_file);
    assert!(
        sshd_log.contains(&agent_fingerprint),
        "sshd log must record the enrolled Agent key fingerprint"
    );
    assert!(
        sshd_log.contains(&controller_fingerprint),
        "sshd log must record the Controller key fingerprint"
    );
    println!(
        "redacted gateway auth receipt: source_sha={} agent_reverse_key=accepted_from_hub_v2_projection controller_gateway_key=accepted wildcard_reverse=denied revoke_projection=reconciled active_session=not_terminated",
        std::env::var("HOSTLINK_SOURCE_SHA").unwrap_or_else(|_| "unrecorded".into())
    );
    assert!(
        children.stop_all(),
        "all temporary fixture process groups must terminate"
    );
    let cleanup_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let current_pids = Command::new("pgrep")
            .args(["-x", "sshd"])
            .output()
            .expect("inspect sshd processes after fixture")
            .stdout;
        let current_port = Command::new("ss")
            .args(["-ltn", "sport", "=", ":22"])
            .output()
            .expect("inspect port 22 after fixture")
            .stdout;
        if current_pids == old_ssh_pids && current_port == old_ssh_port {
            break;
        }
        assert!(
            Instant::now() < cleanup_deadline,
            "temporary child processes must exit, pre-existing sshd PIDs and port 22 must stay unchanged"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn connect_retry(spec: &hostlink::HostSpec) -> HostConnection {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(connection) = HostConnection::connect(spec).await {
            return connection;
        }
        assert!(
            Instant::now() < deadline,
            "managed nested SSH route did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
