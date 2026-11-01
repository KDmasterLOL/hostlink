#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn hostlink(args: &[&str], config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
        .env("HOSTLINK_HUB_CONFIG", config)
        // Release tests must never consult a developer's real GitHub PAT.
        .env(
            "XDG_CONFIG_HOME",
            config.parent().unwrap().join("missing-test-config"),
        )
        .output()
        .expect("start hostlink CLI")
}

#[test]
fn invite_selects_only_github_release_and_keeps_token_only_mode() {
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
        "--version",
        "--target",
        "--bootstrap-hub-ca-cert",
    ] {
        assert!(
            help.contains(option),
            "missing {option} from invite interface: {help}"
        );
    }
    for removed in [
        "--installer-url",
        "--installer-sha256",
        "--agent-url",
        "--agent-sha256",
        "--archive-url",
        "--archive-sha256",
    ] {
        assert!(
            !help.contains(removed),
            "obsolete arbitrary-site flag survived: {removed}"
        );
    }
}

#[test]
fn invalid_target_or_missing_github_credential_fail_before_any_hub_invite_request() {
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

    let invalid_target = hostlink(
        &[
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "unsupported-target",
        ],
        &config,
    );
    assert!(!invalid_target.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_target.stderr).contains("unsupported bootstrap target")
    );

    let output = hostlink(
        &[
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "x86_64-win7-windows-msvc",
        ],
        &config,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GitHub credential"), "{stderr}");
    assert!(!stderr.contains("disposable-operator-token"));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "invalid artifact selection must fail before any Hub POST"
    );
}
