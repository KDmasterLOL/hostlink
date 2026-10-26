#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn hostlink(args: &[&str], config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
        .env("HOSTLINK_HUB_CONFIG", config)
        .output()
        .expect("start hostlink CLI")
}

#[test]
fn invite_requires_source_pins_by_default_and_exposes_explicit_manual_mode() {
    let help = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(["invite", "--help"])
        .output()
        .expect("start hostlink CLI help");
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    for option in [
        "--token-only",
        "--ssh-user",
        "--installer-url",
        "--installer-sha256",
        "--agent-url",
        "--agent-sha256",
        "--archive-url",
        "--archive-sha256",
        "--version",
        "--target",
        "--bootstrap-hub-ca-cert",
    ] {
        assert!(
            help.contains(option),
            "missing {option} from invite interface: {help}"
        );
    }
}

#[test]
fn invalid_source_target_is_rejected_before_any_hub_invite_request() {
    let root = tempfile::tempdir().expect("temporary config directory");
    let token = root.path().join("operator.token");
    fs::write(&token, "disposable-operator-token").expect("write token fixture");
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("protect token fixture");
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIP Hub POST boundary fixture: sandbox denied loopback bind: {error}");
            return;
        }
        Err(error) => panic!("bind disposable Hub boundary fixture: {error}"),
    };
    listener
        .set_nonblocking(true)
        .expect("make fixture nonblocking");
    let hub_url = format!(
        "https://{}",
        listener.local_addr().expect("read fixture address")
    );
    let config = root.path().join("hub.json");
    fs::write(
        &config,
        serde_json::json!({
            "hub_url": hub_url,
            "token_file": token,
            "ssh_user": "hostlink",
            "identity": "unused-controller-key",
            "gateway_identity": "unused-gateway-key"
        })
        .to_string(),
    )
    .expect("write Hub config fixture");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("protect config fixture");

    let missing = hostlink(
        &[
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "x86_64-win7-windows-msvc",
        ],
        &config,
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--installer-url is required"));

    let output = hostlink(
        &[
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "x86_64-win7-windows-msvc",
            "--version",
            "1.2.3",
            "--installer-url",
            "https://artifacts.example/install.ps1",
            "--installer-sha256",
            &"a".repeat(64),
            "--agent-url",
            "https://artifacts.example/x86_64-win7-windows-msvc/hostlink-agent.exe",
            "--agent-sha256",
            &"b".repeat(64),
            "--archive-url",
            "https://artifacts.example/hostlink-agent-x86_64-pc-windows-msvc.zip",
            "--archive-sha256",
            &"c".repeat(64),
        ],
        &config,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ZIP URL must name the exact selected target"),
        "{stderr}"
    );
    assert!(!stderr.contains("disposable-operator-token"));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "invalid artifact selection must fail before any Hub POST"
    );
}
