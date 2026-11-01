use std::process::Command;

fn hostlink(args: &[&str]) -> std::process::Output {
    let root = tempfile::tempdir().expect("temporary CLI config directory");
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
        .env("HOSTLINK_HUB_CONFIG", root.path().join("missing-hub.json"))
        .output()
        .expect("start hostlink CLI")
}

#[test]
fn named_target_is_a_supported_alternative_to_explicit_config() {
    let accepted = hostlink(&["exec", "--host", "lab-win7", "--command", "true"]);
    assert!(!accepted.status.success());
    assert!(!String::from_utf8_lossy(&accepted.stderr).contains("cannot be used with"));

    let both = hostlink(&[
        "exec",
        "--host",
        "lab-win7",
        "--config",
        "host.json",
        "--command",
        "true",
    ]);
    assert!(!both.status.success());
    assert!(String::from_utf8_lossy(&both.stderr).contains("cannot be used with"));
}

#[test]
fn host_target_is_required_before_any_connection_attempt() {
    let output = hostlink(&["check"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("required"));
}

#[cfg(unix)]
#[test]
fn explicit_config_is_independent_of_default_hub_environment() {
    let root = tempfile::tempdir().expect("temporary CLI config directory");
    let invalid_hub = root.path().join("hub.json");
    std::fs::write(&invalid_hub, "invalid Hub config").expect("write invalid Hub config");
    let missing_host = root.path().join("missing-host.json");
    for command in remote_commands() {
        let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
            .env_remove("HOME")
            .env("HOSTLINK_HUB_CONFIG", &invalid_hub)
            .args(*command)
            .arg("--config")
            .arg(&missing_host)
            .output()
            .expect("start hostlink CLI without HOME");
        assert_eq!(output.status.code(), Some(1), "{command:?}");
        assert!(output.stdout.is_empty(), "{command:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("No such file or directory"),
            "{command:?}: explicit --config must read that file without consulting Hub or HOME: {stderr}"
        );
    }
}

fn remote_commands() -> &'static [&'static [&'static str]] {
    &[
        &["check"],
        &["exec", "--command", "true"],
        &["upload", "--local", "input.bin", "--remote", "input.bin"],
        &[
            "download",
            "--remote",
            "output.bin",
            "--local",
            "output.bin",
        ],
        &[
            "forward",
            "--listen",
            "127.0.0.1:13389",
            "--target",
            "127.0.0.1:3389",
        ],
        &["rdp"],
        &["probe", "--target", "127.0.0.1:443"],
    ]
}

#[test]
fn remote_commands_accept_exactly_one_host_selection() {
    for command in remote_commands() {
        let mut selected = command.to_vec();
        selected.extend(["--host", "lab-win7"]);
        let output = hostlink(&selected);
        assert_eq!(output.status.code(), Some(1), "{command:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument") && !stderr.contains("required arguments"),
            "named host selector was rejected by the CLI: {stderr}"
        );

        let mut both = command.to_vec();
        both.extend(["--host", "lab-win7", "--config", "host.json"]);
        let output = hostlink(&both);
        assert_eq!(output.status.code(), Some(2), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "both host selection methods must be rejected"
        );

        let output = hostlink(command);
        assert_eq!(output.status.code(), Some(2), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("required"),
            "missing host selector must be rejected"
        );
    }
}

#[test]
fn remote_help_preserves_selector_names_and_command_options() {
    for command in remote_commands() {
        let output = hostlink(&[command[0], "--help"]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("--config <CONFIG>"), "{help}");
        assert!(help.contains("--host <HOST>"), "{help}");
        for option in command.iter().filter(|arg| arg.starts_with("--")) {
            assert!(help.contains(option), "missing {option}: {help}");
        }
    }
}

// Exercise the CLI against the actual Agent in a disposable loopback fixture.
#[cfg(unix)]
#[tokio::test]
#[ignore = "requires loopback SSH and a local Agent; run explicitly for transport acceptance"]
async fn remote_cli_preserves_exit_status_transfers_and_local_errors() {
    use hostlink_agent::{AgentConfig, ssh};
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_key = root.path().join("host-key");
    let identity = root.path().join("controller-key");
    let authorized_keys = root.path().join("authorized_keys");
    for (path, bytes) in [
        (
            &host_key,
            host.to_openssh(LineEnding::LF).unwrap().to_string(),
        ),
        (
            &identity,
            controller.to_openssh(LineEnding::LF).unwrap().to_string(),
        ),
        (
            &authorized_keys,
            controller.public_key().to_openssh().unwrap(),
        ),
    ] {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let jobs_root = root.path().join("jobs");
    fs::create_dir(&jobs_root).unwrap();
    fs::set_permissions(&jobs_root, fs::Permissions::from_mode(0o700)).unwrap();
    hostlink_agent::jobs::JobStore::initialize_fresh(&jobs_root)
        .await
        .unwrap()
        .close()
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let config = AgentConfig {
        listen: endpoint,
        user: "hostlink".into(),
        host_key,
        authorized_keys,
        jobs_root,
        board_listen: None,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let host_config = root.path().join("host.json");
    fs::write(
        &host_config,
        serde_json::to_vec(&serde_json::json!({
            "endpoint": endpoint,
            "user": "hostlink",
            "identity": identity,
            "host_public_key": host.public_key().to_openssh().unwrap(),
            "gateway": null,
        }))
        .unwrap(),
    )
    .unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = stop_rx.await;
        })
        .await
    });
    let input = root.path().join("input.bin");
    let output = root.path().join("output.bin");
    let missing = root.path().join("missing.bin");
    let bytes = b"CLI binary payload\x00\xff";
    fs::write(&input, bytes).unwrap();
    let cases = [
        (vec!["check"], 0),
        (
            vec![
                "exec",
                "--command",
                "cat; exit 7",
                "--stdin-file",
                input.to_str().unwrap(),
            ],
            7,
        ),
        (
            vec![
                "upload",
                "--local",
                input.to_str().unwrap(),
                "--remote",
                "payload.bin",
            ],
            0,
        ),
        (
            vec![
                "download",
                "--remote",
                "payload.bin",
                "--local",
                output.to_str().unwrap(),
            ],
            0,
        ),
        (
            vec![
                "exec",
                "--command",
                "exit 0",
                "--stdin-file",
                missing.to_str().unwrap(),
            ],
            1,
        ),
        (
            vec![
                "upload",
                "--local",
                missing.to_str().unwrap(),
                "--remote",
                "missing.bin",
            ],
            1,
        ),
        (
            vec![
                "download",
                "--remote",
                "payload.bin",
                "--local",
                output.to_str().unwrap(),
            ],
            1,
        ),
    ];
    let mut results = Vec::new();
    for (args, code) in cases {
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_hostlink"))
                .args(&args)
                .arg("--config")
                .arg(&host_config)
                .env("HOME", root.path())
                .env("HOSTLINK_HUB_CONFIG", root.path().join("missing-hub.json"))
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("CLI operation deadline")
        .expect("start CLI against disposable Agent");
        results.push((args, code, result));
    }
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("Agent shutdown deadline")
        .unwrap()
        .unwrap();
    for (args, code, result) in results {
        assert_eq!(
            result.status.code(),
            Some(code),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        if code == 7 {
            assert_eq!(result.stdout, bytes);
            assert!(result.stderr.is_empty());
        } else if code == 1 {
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8_lossy(&result.stderr).starts_with("hostlink: "));
        }
    }
    assert_eq!(fs::read(output).unwrap(), bytes);
}
