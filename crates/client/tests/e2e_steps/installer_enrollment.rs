use super::enrollment::EnrollmentContext;
use super::*;

pub(super) fn invite_for_installer(
    context: &EnrollmentContext<'_>,
    plan: &installer::InstallerPlan,
) -> (String, String) {
    let mut invite = Command::new(context.client_bin);
    cli_env(&mut invite, context.cli_config);
    let invited = run_ok(
        invite.args(&plan.args),
        "actual source-pinned hostlink invite command",
    );
    let invited = String::from_utf8(invited.stdout).expect("invite output is UTF-8");
    let token = invited
        .lines()
        .find_map(|line| line.strip_prefix("token: "))
        .expect("CLI prints separate one-use token")
        .to_owned();
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
    (token, command.to_owned())
}

pub(super) fn verify_bootstrap_rejections(
    context: &mut EnrollmentContext<'_>,
    plan: &installer::InstallerPlan,
    token: &str,
    command: &str,
) {
    let xdg_data = context.root.join("target-data");
    private_dir(&xdg_data);
    let wrong_ca_path = context.root.join("wrong-ca.pem");
    let rejected_ca_command = command.replace(
        &context.ca_cert.to_string_lossy().to_string(),
        &wrong_ca_path.to_string_lossy(),
    );
    assert_ne!(
        rejected_ca_command, command,
        "expected pinned CA in rendered command"
    );
    let wrong_ca_output = expect_bootstrap_rejection(
        context.children,
        context.root,
        &xdg_data,
        &wrong_ca_path,
        &rejected_ca_command,
        "bootstrap-wrong-ca",
    );
    assert!(!wrong_ca_output.contains(token));

    for (path, label) in [
        (&plan.sidecar, "bootstrap-wrong-sidecar-digest"),
        (&plan.archive, "bootstrap-wrong-archive-digest"),
    ] {
        let original = fs::read(path).unwrap();
        let mut tampered = original.clone();
        tampered.push(0);
        fs::write(path, tampered).unwrap();
        let output = expect_bootstrap_rejection(
            context.children,
            context.root,
            &xdg_data,
            context.ca_cert,
            command,
            label,
        );
        assert!(!output.contains(token));
        fs::write(path, original).unwrap();
    }
}

pub(super) fn run_interactive_installer(
    context: &mut EnrollmentContext<'_>,
    plan: &installer::InstallerPlan,
    token: &str,
    command: &str,
) -> PathBuf {
    let xdg_data = context.root.join("target-data");
    let shell_command = format!("/bin/sh -c {}", sh_quote(command));
    let install_log = context.root.join("installer-pty.log");
    let mut terminal = Command::new("script");
    terminal
        .args(["-qefc", &shell_command, "/dev/null"])
        .env("SHELL", "/bin/sh")
        .env("HOME", context.root)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("CURL_CA_BUNDLE", context.ca_cert)
        .env("SSL_CERT_FILE", context.ca_cert)
        .stdin(Stdio::piped())
        .stdout(private_log(&install_log))
        .stderr(Stdio::null());
    context.children.start(terminal);
    let index = context.children.children.len() - 1;
    let deadline = Instant::now() + Duration::from_secs(90);
    wait_for_installer_prompt(context, index, &install_log, deadline);
    let process_id = context.children.children[index].id();
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
    let stdin = context.children.children[index]
        .stdin
        .as_mut()
        .expect("interactive installer stdin remains open");
    stdin.write_all(token.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
    wait_for_installer_completion(context, index, &install_log, token, deadline);
    println!(
        "source-pinned installer receipt: source_sha={} target={} version={} installer_sha256={} agent_sha256={} archive_sha256={} token_separate=true token_argv_or_env=false",
        std::env::var("HOSTLINK_SOURCE_SHA").unwrap_or_else(|_| "unrecorded".into()),
        plan.target,
        plan.version,
        plan.installer_sha,
        plan.agent_sha,
        plan.archive_sha,
    );
    fs::read_dir(&xdg_data)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("Agent/state"))
        .find(|path| path.join("agent.json").is_file())
        .expect("installer created a new owner-private Agent root")
}

fn wait_for_installer_prompt(
    context: &mut EnrollmentContext<'_>,
    index: usize,
    install_log: &Path,
    deadline: Instant,
) {
    loop {
        let output = fs::read_to_string(install_log).unwrap_or_default();
        if output.contains("One-use HostLink invite token:") {
            return;
        }
        if let Some(status) = context.children.children[index]
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
}

fn wait_for_installer_completion(
    context: &mut EnrollmentContext<'_>,
    index: usize,
    install_log: &Path,
    token: &str,
    deadline: Instant,
) {
    loop {
        let output = fs::read_to_string(install_log).unwrap_or_default();
        if output.contains("Enrollment complete. Starting the embedded Agent") {
            assert!(
                !output.contains(token),
                "PTY transcript must not echo the token"
            );
            return;
        }
        if let Some(status) = context.children.children[index]
            .try_wait()
            .expect("inspect Agent after installer")
        {
            panic!("installer/Agent exited before enrollment completed: {status}; log: {output}");
        }
        assert!(
            Instant::now() < deadline,
            "verified installer enrollment deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
