#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn hostlink(args: &[&str], config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
        .env("HOSTLINK_HUB_CONFIG", config)
        .env("HOME", config.parent().unwrap())
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
        "--embed-github-token",
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
    let hub_url = "https://127.0.0.1:1";
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
    assert_eq!(invalid_target.status.code(), Some(2));
    assert!(invalid_target.stdout.is_empty());
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
    let embedded = hostlink(
        &[
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "x86_64-win7-windows-msvc",
            "--embed-github-token",
        ],
        &config,
    );
    assert!(!embedded.status.success());
    assert!(String::from_utf8_lossy(&embedded.stderr).contains("GitHub credential"));
    assert!(!String::from_utf8_lossy(&embedded.stdout).contains("token:"));
    assert!(!stderr.contains("Hub request"), "{stderr}");
}

#[test]
fn invalid_invitation_target_is_rejected_before_reading_hub_configuration() {
    let root = tempfile::tempdir().expect("temporary config directory");
    for embed in [false, true] {
        let mut args = vec![
            "invite",
            "--name",
            "lab-win7",
            "--target",
            "unsupported-target",
        ];
        if embed {
            args.push("--embed-github-token");
        }
        let output = hostlink(&args, &root.path().join("missing-hub.json"));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("unsupported bootstrap target"), "{stderr}");
        assert!(!stderr.contains("No such file"), "{stderr}");
    }
}
