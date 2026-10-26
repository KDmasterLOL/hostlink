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
    io::Write,
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

fn write_caddyfile(
    path: &Path,
    url_port: u16,
    cert: &Path,
    key: &Path,
    hub: SocketAddr,
    artifacts: &Path,
) {
    let content = format!(
        "{{\n  admin off\n  auto_https off\n}}\nhttps://localhost:{url_port} {{\n  bind 127.0.0.1\n  tls {} {}\n  route {{\n    @redirect path /redirect\n    redir @redirect /0.1.0/install-hostlink-agent.sh 302\n    @hub path /v2/*\n    handle @hub {{\n      reverse_proxy http://{}\n    }}\n    handle {{\n      root * {}\n      file_server\n    }}\n  }}\n}}\n",
        cert.display(),
        key.display(),
        hub,
        artifacts.display()
    );
    private_write(path, content);
}

fn cli_env(command: &mut Command, config: &Path) {
    command.env("HOSTLINK_HUB_CONFIG", config);
}

fn invite_args(
    installer_url: &str,
    installer_sha: &str,
    agent_url: &str,
    agent_sha: &str,
    archive_url: &str,
    archive_sha: &str,
) -> Vec<String> {
    [
        "invite",
        "--name",
        "managed-fixture",
        "--ssh-user",
        &std::env::var("USER").unwrap(),
        "--ttl-seconds",
        "900",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--version",
        "0.1.0",
        "--installer-url",
        installer_url,
        "--installer-sha256",
        installer_sha,
        "--agent-url",
        agent_url,
        "--agent-sha256",
        agent_sha,
        "--archive-url",
        archive_url,
        "--archive-sha256",
        archive_sha,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn file_sha256(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read pinned artifact"))
    )
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn expect_bootstrap_rejection(
    children: &mut Children,
    root: &Path,
    xdg_data: &Path,
    ca_bundle: &Path,
    command: &str,
    label: &str,
) -> String {
    let log = root.join(format!("{label}.pty.log"));
    let shell_command = format!("/bin/sh -c {}", sh_quote(command));
    let mut terminal = Command::new("script");
    terminal
        .args(["-qefc", &shell_command, "/dev/null"])
        // util-linux script uses $SHELL to evaluate -c. The HOME operator's
        // login shell is Nushell, but this is a POSIX /bin/sh bootstrap;
        // otherwise Nushell reparses quoting and breaks the trap directive.
        .env("SHELL", "/bin/sh")
        .env("HOME", root)
        .env("XDG_DATA_HOME", xdg_data)
        .env("CURL_CA_BUNDLE", ca_bundle)
        .env("SSL_CERT_FILE", ca_bundle)
        .stdin(Stdio::piped())
        .stdout(private_log(&log))
        .stderr(Stdio::null());
    children.start(terminal);
    let index = children.children.len() - 1;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = fs::read_to_string(&log).unwrap_or_default();
        if output.contains("One-use HostLink invite token:") {
            // SAFETY: Children::start puts this exact fixture command in its own process group.
            unsafe {
                libc::kill(-(children.children[index].id() as i32), libc::SIGKILL);
            }
            let _ = children.children[index].wait();
            panic!("{label} reached token prompt before rejection: {output}");
        }
        if let Some(status) = children.children[index]
            .try_wait()
            .expect("inspect rejected bootstrap process")
        {
            assert!(!status.success(), "{label} unexpectedly succeeded");
            return output;
        }
        assert!(Instant::now() < deadline, "{label} rejection deadline");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires openssh-server, Caddy, OpenSSL, and the fixture script"]
async fn actual_https_hub_enrollment_openssh_projection_and_managed_russh_flow() {
    run_managed_https_gateway_fixture(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires openssh-server, Caddy, OpenSSL, packaged artifacts, and the fixture script"]
async fn actual_cli_invite_https_installer_enrollment_and_managed_russh_flow() {
    run_managed_https_gateway_fixture(true).await;
}

async fn run_managed_https_gateway_fixture(installer_flow: bool) {
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
    let artifact_root = std::env::var_os("HOSTLINK_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .expect("fixture script packages immutable Agent artifacts");
    let tls_config = root.path().join("Caddyfile");
    write_caddyfile(
        &tls_config,
        tls_port,
        &leaf_cert,
        &leaf_key,
        hub_listener,
        &artifact_root,
    );
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
    let cli_config = root.path().join("controller-hub.json");
    let mut configure = Command::new(&client_bin);
    cli_env(&mut configure, &cli_config);
    run_ok(
        configure
            .args(["hub", "configure", "--hub-url", &tls_url, "--hub-ca-cert"])
            .arg(&ca_cert)
            .args(["--token-file"])
            .arg(&token_file)
            .args(["--ssh-user"])
            .arg(std::env::var("USER").unwrap())
            .args(["--identity"])
            .arg(&controller_key)
            .args(["--gateway-identity"])
            .arg(&controller_key),
        "actual Hub controller configuration command",
    );
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

    let enrollment_token = root.path().join("enrollment.token");
    let mut replay_token = None;
    let agent_root = if installer_flow {
        let version = "0.1.0";
        let target = "x86_64-unknown-linux-gnu";
        let installer = artifact_root
            .join(version)
            .join("install-hostlink-agent.sh");
        let sidecar = artifact_root
            .join(version)
            .join(target)
            .join("hostlink-agent");
        let archive = artifact_root
            .join(version)
            .join(format!("hostlink-agent-{target}.zip"));
        let installer_url = format!("{tls_url}/{version}/install-hostlink-agent.sh");
        let agent_url = format!("{tls_url}/{version}/{target}/hostlink-agent");
        let archive_url = format!("{tls_url}/{version}/hostlink-agent-{target}.zip");
        let installer_sha = file_sha256(&installer);
        let agent_sha = file_sha256(&sidecar);
        let archive_sha = file_sha256(&archive);
        let mut args = invite_args(
            &installer_url,
            &installer_sha,
            &agent_url,
            &agent_sha,
            &archive_url,
            &archive_sha,
        );
        args.extend([
            "--bootstrap-hub-ca-cert".into(),
            ca_cert.to_string_lossy().into_owned(),
        ]);

        let wrong_ca_config = root.path().join("wrong-ca-controller.json");
        private_write(
            &wrong_ca_config,
            serde_json::to_vec_pretty(&HubConfig {
                hub_ca_cert: Some(root.path().join("wrong-ca.pem")),
                ..controller_config.clone()
            })
            .unwrap(),
        );
        let mut wrong_ca_invite = Command::new(&client_bin);
        cli_env(&mut wrong_ca_invite, &wrong_ca_config);
        assert!(
            !wrong_ca_invite
                .args(&args)
                .status()
                .expect("wrong artifact CA")
                .success(),
            "installer preflight must reject an untrusted HTTPS CA before invitation"
        );

        let mut wrong_installer_pin = args.clone();
        let installer_pin_index = wrong_installer_pin
            .iter()
            .position(|value| value == "--installer-sha256")
            .unwrap()
            + 1;
        wrong_installer_pin[installer_pin_index] = "0".repeat(64);
        let mut bad_pin_invite = Command::new(&client_bin);
        cli_env(&mut bad_pin_invite, &cli_config);
        let bad_pin = bad_pin_invite
            .args(&wrong_installer_pin)
            .output()
            .expect("wrong installer digest preflight");
        assert!(!bad_pin.status.success());
        assert!(!String::from_utf8_lossy(&bad_pin.stdout).contains("token:"));

        let wrong_host_url = installer_url.replace("localhost", "127.0.0.1");
        let mut wrong_host_args = args.clone();
        let installer_url_index = wrong_host_args
            .iter()
            .position(|value| value == "--installer-url")
            .unwrap()
            + 1;
        let sidecar_url_index = wrong_host_args
            .iter()
            .position(|value| value == "--agent-url")
            .unwrap()
            + 1;
        let archive_url_index = wrong_host_args
            .iter()
            .position(|value| value == "--archive-url")
            .unwrap()
            + 1;
        wrong_host_args[installer_url_index] = wrong_host_url.clone();
        wrong_host_args[sidecar_url_index] = agent_url.replace("localhost", "127.0.0.1");
        wrong_host_args[archive_url_index] = archive_url.replace("localhost", "127.0.0.1");
        let mut wrong_host_invite = Command::new(&client_bin);
        cli_env(&mut wrong_host_invite, &cli_config);
        assert!(
            !wrong_host_invite
                .args(&wrong_host_args)
                .status()
                .expect("wrong artifact hostname")
                .success(),
            "installer preflight must reject a hostname mismatch before invitation"
        );

        let mut redirected_args = args.clone();
        redirected_args[installer_url_index] = format!("{tls_url}/redirect");
        let mut redirected_invite = Command::new(&client_bin);
        cli_env(&mut redirected_invite, &cli_config);
        assert!(
            !redirected_invite
                .args(&redirected_args)
                .status()
                .expect("redirected installer source")
                .success(),
            "installer preflight must refuse HTTPS redirects before invitation"
        );

        let mut invite = Command::new(&client_bin);
        cli_env(&mut invite, &cli_config);
        let invited = run_ok(
            invite.args(&args),
            "actual source-pinned hostlink invite command",
        );
        let invited = String::from_utf8(invited.stdout).expect("invite output is UTF-8");
        let token = invited
            .lines()
            .find_map(|line| line.strip_prefix("token: "))
            .expect("CLI prints separate one-use token")
            .to_owned();
        replay_token = Some(token.clone());
        assert_eq!(token.len(), 64);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(invited.contains("artifact_binding: verified"));
        let command = invited
            .split_once("bootstrap_command:\n")
            .expect("CLI renders the runnable bootstrap")
            .1
            .trim_end();
        assert!(
            !command.contains(&token),
            "token stays outside copyable command"
        );
        assert!(!command.contains('\0'));

        let xdg_data = root.path().join("target-data");
        private_dir(&xdg_data);
        let shell_command = format!("/bin/sh -c {}", sh_quote(command));
        let wrong_ca_output = expect_bootstrap_rejection(
            &mut children,
            root.path(),
            &xdg_data,
            &root.path().join("wrong-ca.pem"),
            command,
            "bootstrap-wrong-ca",
        );
        assert!(!wrong_ca_output.contains(&token));

        let sidecar_bytes = fs::read(&sidecar).unwrap();
        let mut modified_sidecar = sidecar_bytes.clone();
        modified_sidecar.push(0);
        fs::write(&sidecar, modified_sidecar).unwrap();
        let sidecar_output = expect_bootstrap_rejection(
            &mut children,
            root.path(),
            &xdg_data,
            &ca_cert,
            command,
            "bootstrap-wrong-sidecar-digest",
        );
        assert!(!sidecar_output.contains(&token));
        fs::write(&sidecar, &sidecar_bytes).unwrap();

        let archive_bytes = fs::read(&archive).unwrap();
        let mut modified_archive = archive_bytes.clone();
        modified_archive.push(0);
        fs::write(&archive, modified_archive).unwrap();
        let archive_output = expect_bootstrap_rejection(
            &mut children,
            root.path(),
            &xdg_data,
            &ca_cert,
            command,
            "bootstrap-wrong-archive-digest",
        );
        assert!(!archive_output.contains(&token));
        fs::write(&archive, &archive_bytes).unwrap();

        let install_log = root.path().join("installer-pty.log");
        let mut terminal = Command::new("script");
        terminal
            .args(["-qefc", &shell_command, "/dev/null"])
            .env("SHELL", "/bin/sh")
            .env("HOME", root.path())
            .env("XDG_DATA_HOME", &xdg_data)
            .env("CURL_CA_BUNDLE", &ca_cert)
            .env("SSL_CERT_FILE", &ca_cert)
            .stdin(Stdio::piped())
            .stdout(private_log(&install_log))
            .stderr(Stdio::null());
        children.start(terminal);
        let index = children.children.len() - 1;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let output = fs::read_to_string(&install_log).unwrap_or_default();
            if output.contains("One-use HostLink invite token:") {
                break;
            }
            if let Some(status) = children.children[index]
                .try_wait()
                .expect("inspect interactive installer")
            {
                panic!("installer exited before token prompt: {status}; log: {output}");
            }
            assert!(
                Instant::now() < deadline,
                "verified installer token prompt deadline"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let process_id = children.children[index].id();
        let process_argv = fs::read(format!("/proc/{process_id}/cmdline")).unwrap_or_default();
        let process_env = fs::read(format!("/proc/{process_id}/environ")).unwrap_or_default();
        assert!(
            !process_argv
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
        assert!(
            !process_env
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
        let stdin = children.children[index]
            .stdin
            .as_mut()
            .expect("interactive installer stdin remains open");
        stdin.write_all(token.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        loop {
            let output = fs::read_to_string(&install_log).unwrap_or_default();
            if output.contains("Enrollment complete. Starting the embedded Agent") {
                assert!(
                    !output.contains(&token),
                    "PTY transcript must not echo the token"
                );
                break;
            }
            if let Some(status) = children.children[index]
                .try_wait()
                .expect("inspect Agent after installer")
            {
                panic!(
                    "installer/Agent exited before enrollment completed: {status}; log: {output}"
                );
            }
            assert!(
                Instant::now() < deadline,
                "verified installer enrollment deadline"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        println!(
            "source-pinned installer receipt: source_sha={} target={} version={} installer_sha256={} agent_sha256={} archive_sha256={} token_separate=true token_argv_or_env=false",
            std::env::var("HOSTLINK_SOURCE_SHA").unwrap_or_else(|_| "unrecorded".into()),
            target,
            version,
            installer_sha,
            agent_sha,
            archive_sha,
        );
        let dirs = fs::read_dir(&xdg_data)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("Agent/state"))
            .collect::<Vec<_>>();
        dirs.into_iter()
            .find(|path| path.join("agent.json").is_file())
            .expect("installer created a new owner-private Agent root")
    } else {
        let invite = hub_client
            .invite(Some("managed-fixture".into()), 900)
            .await
            .expect("create one-use invite over HTTPS");
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
        root.path().join("agent-root/state")
    };
    if installer_flow {
        use std::os::unix::fs::MetadataExt;
        let installed_root = agent_root
            .parent()
            .expect("Agent state has a private parent");
        let metadata = fs::metadata(installed_root).expect("inspect installed Agent root");
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    let agent_config: serde_json::Value =
        serde_json::from_slice(&fs::read(agent_root.join("agent.json")).unwrap()).unwrap();
    if let Some(token) = replay_token.as_deref() {
        private_write(&enrollment_token, token);
    }
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
    if !installer_flow {
        let mut agent_run = Command::new(&agent_bin);
        agent_run
            .args(["run", "--config"])
            .arg(agent_root.join("agent.json"))
            .stdout(private_log(&root.path().join("agent.stdout.log")))
            .stderr(private_log(&root.path().join("agent.stderr.log")));
        children.start(agent_run);
    }
    wait_port(agent_listen, None);

    // Controller's normal config and CLI use the private CA field and name selector.
    let mut list = Command::new(&client_bin);
    cli_env(&mut list, &cli_config);
    let listed = run_ok(list.args(["list"]), "Hub-backed name inventory");
    assert!(String::from_utf8_lossy(&listed.stdout).contains("managed-fixture"));
    let mut verify = Command::new(&client_bin);
    cli_env(&mut verify, &cli_config);
    let verified = run_ok(
        verify.args(["verify", "managed-fixture"]),
        "Hub-backed host verification through pinned SSH",
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("verified managed-fixture"));
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
    let local_upload = root.path().join("controller-upload.bin");
    let local_download = root.path().join("controller-download.bin");
    private_write(&local_upload, artifact);
    let mut upload = Command::new(&client_bin);
    cli_env(&mut upload, &cli_config);
    run_ok(
        upload
            .args(["upload", "--host", "managed-fixture", "--local"])
            .arg(&local_upload)
            .args(["--remote", "controller-cli-roundtrip.bin"]),
        "managed CLI SFTP upload",
    );
    let mut download = Command::new(&client_bin);
    cli_env(&mut download, &cli_config);
    run_ok(
        download
            .args([
                "download",
                "--host",
                "managed-fixture",
                "--remote",
                "controller-cli-roundtrip.bin",
                "--local",
            ])
            .arg(&local_download),
        "managed CLI SFTP download",
    );
    assert_eq!(fs::read(local_download).unwrap(), artifact);

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
