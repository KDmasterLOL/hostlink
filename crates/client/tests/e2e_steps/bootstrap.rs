use super::*;

pub(super) fn invite_args(
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

pub(super) fn file_sha256(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read pinned artifact"))
    )
}

pub(super) fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn expect_bootstrap_rejection(
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
