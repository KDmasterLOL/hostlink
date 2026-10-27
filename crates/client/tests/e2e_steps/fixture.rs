use super::*;

pub(super) struct Children {
    pub(super) children: Vec<Child>,
    pub(super) stopped: bool,
}

impl Children {
    pub(super) fn start(&mut self, mut command: Command) -> &mut Child {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let child = command
            .spawn()
            .expect("start private fixture child process");
        self.children.push(child);
        self.children.last_mut().expect("just inserted child")
    }

    pub(super) fn stop_all(&mut self) -> bool {
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

pub(super) fn private_dir(path: &Path) {
    fs::create_dir_all(path).expect("create fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("set private mode");
}

pub(super) fn private_write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("write private fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set private mode");
}

pub(super) fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

pub(super) fn wait_port(address: SocketAddr, mut child: Option<&mut Child>) {
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

pub(super) fn key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("generate disposable key")
}

pub(super) fn private_key_file(path: &Path, key: &PrivateKey) {
    private_write(path, key.to_openssh(LineEnding::LF).expect("serialize key"));
}

pub(super) fn public_key(key: &PrivateKey) -> String {
    key.public_key().to_openssh().expect("serialize public key")
}

pub(super) fn ssh_fingerprint(public_key_file: &Path) -> String {
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

pub(super) fn run_ok(command: &mut Command, what: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|_| panic!("run {what}"));
    assert!(
        output.status.success(),
        "{what} failed with status {}",
        output.status
    );
    output
}

pub(super) fn write_server_certificate(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
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

pub(super) fn private_log(path: &Path) -> Stdio {
    Stdio::from(fs::File::create(path).expect("create private process log"))
}

pub(super) fn cli_env(command: &mut Command, config: &Path) {
    command.env("HOSTLINK_HUB_CONFIG", config);
}
