#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn hostlink(args: &[&str], config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
        .env("HOSTLINK_HUB_CONFIG", config)
        .env("HOME", config.parent().unwrap())
        // Keep fixture resolution isolated from the developer configuration.
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
        "--os",
        "--bootstrap-hub-ca-cert",
    ] {
        assert!(
            help.contains(option),
            "missing {option} from invite interface: {help}"
        );
    }
    for removed in [
        "--embed-github-token",
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
fn invalid_target_fails_without_contacting_hub() {
    let root = tempfile::tempdir().expect("temporary config directory");
    // The config is HostLink-managed state, not an arbitrary public fixture.
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect managed config directory");
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
}

#[test]
fn invalid_invitation_target_is_rejected_before_reading_hub_configuration() {
    let root = tempfile::tempdir().expect("temporary config directory");
    let args = [
        "invite",
        "--name",
        "lab-win7",
        "--target",
        "unsupported-target",
    ];
    let output = hostlink(&args, &root.path().join("missing-hub.json"));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported bootstrap target"), "{stderr}");
    assert!(!stderr.contains("No such file"), "{stderr}");
}
