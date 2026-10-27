use super::*;

pub(super) struct SshFixture {
    pub(super) operator: PrivateKey,
    pub(super) controller_key: PathBuf,
    pub(super) ssh_port: u16,
    pub(super) test_gateway_known_hosts: PathBuf,
    pub(super) sshd_config: PathBuf,
    pub(super) sshd_bin: PathBuf,
    pub(super) sshd_host_public: String,
}

pub(super) fn start(root: &Path, gateway_root: &Path, children: &mut Children) -> SshFixture {
    let operator = key();
    let sshd_host = root.join("sshd_host_key");
    run_ok(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&sshd_host),
        "generate isolated sshd host key",
    );
    let sshd_host_public =
        fs::read_to_string(format!("{}.pub", sshd_host.display())).expect("read sshd host pin");
    let controller_key = root.join("controller_key");
    private_key_file(&controller_key, &operator);
    let operator_authorized = root.join("controller_authorized_keys");
    private_write(
        &operator_authorized,
        format!("{} hostlink-fixture-controller\n", public_key(&operator)),
    );
    let ssh_port = free_port();
    let test_gateway_known_hosts = root.join("gateway-known-hosts");
    private_write(
        &test_gateway_known_hosts,
        format!("[127.0.0.1]:{ssh_port} {}", sshd_host_public.trim()),
    );
    let sshd_config = root.join("sshd_config");
    private_write(
        &sshd_config,
        format!(
            "Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {} {}\nStrictModes no\nAllowUsers {}\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowTcpForwarding yes\nGatewayPorts no\nX11Forwarding no\nPermitUserEnvironment no\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n",
            sshd_host.display(),
            root.join("sshd.pid").display(),
            operator_authorized.display(),
            gateway_root.join("hostlink-v2-authorized_keys").display(),
            std::env::var("USER").unwrap()
        ),
    );
    let sshd_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_SSHD_BIN").unwrap_or_else(|| "/usr/sbin/sshd".into()),
    );
    run_ok(
        Command::new(&sshd_bin).args(["-t", "-f"]).arg(&sshd_config),
        "validate isolated sshd config",
    );
    let mut sshd = Command::new(&sshd_bin);
    sshd.args(["-D", "-e", "-f"])
        .arg(&sshd_config)
        .stdout(private_log(&root.join("sshd.stdout.log")))
        .stderr(private_log(&root.join("sshd.stderr.log")));
    let sshd_child = children.start(sshd);
    wait_port(
        SocketAddr::from(([127, 0, 0, 1], ssh_port)),
        Some(sshd_child),
    );

    SshFixture {
        operator,
        controller_key,
        ssh_port,
        test_gateway_known_hosts,
        sshd_config,
        sshd_bin,
        sshd_host_public,
    }
}

pub(super) async fn connect_retry(spec: &hostlink::HostSpec) -> HostConnection {
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
