use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn hostlink_binary_name_and_help_are_available_without_target_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .arg("--help")
        .env_remove("ONEC_ACCESS_TARGET")
        .output()
        .expect("run HostLink controller help");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("help UTF-8");
    assert!(help.contains("\nUsage: hostlink "), "{help}");
    assert!(
        help.contains("HostLink managed-machine controller"),
        "{help}"
    );
}

#[test]
fn run_local_rejects_missing_target_before_transport() {
    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args([
            "run-local",
            "--required-effect",
            "read-only",
            "--",
            "./candidate.exe",
        ])
        .env_remove("ONEC_ACCESS_TARGET")
        .output()
        .expect("run hostlink run-local");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "runner diagnostics must not pollute stdout"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr UTF-8");
    assert!(
        stderr.contains("run-local requires --target or ONEC_ACCESS_TARGET"),
        "{stderr}"
    );
}

#[test]
fn run_local_rejects_non_file_candidate_before_target_resolution() {
    let dir = tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args([
            "run-local",
            "--target",
            "unresolved-target",
            "--required-effect",
            "read-only",
            "--",
            dir.path().to_str().expect("UTF-8 temp path"),
        ])
        .output()
        .expect("run hostlink run-local");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "runner stdout must stay clean");
    let stderr = String::from_utf8(output.stderr).expect("stderr UTF-8");
    assert!(stderr.contains("is not a regular file"), "{stderr}");
}

#[test]
fn regression_inv_120_access_cli_uses_one_application_tokio_runtime() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("controller.json");
    let config = serde_json::json!({
        "version": 1,
        "url": "https://127.0.0.1:1",
        "gateway_host": "gateway.example.test",
        "gateway_user": "onec-agent",
        "gateway_port": 22,
        "token_env": "ONEC_HUB_INV120_TOKEN"
    });
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("controller config JSON"),
    )
    .expect("write controller config");

    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(["list", "--json"])
        .env("ONEC_ACCESS_CONFIG", &config_path)
        .env(
            "ONEC_HUB_INV120_TOKEN",
            "inv120-test-operator-token-0123456789abcdef",
        )
        .output()
        .expect("run hostlink list");

    assert!(
        !output.status.success(),
        "synthetic config must fail after client construction"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr UTF-8");
    assert!(
        stderr.contains("hostlink:"),
        "access failure must use normal top-level error handling: {stderr}"
    );
    assert!(
        stderr.contains("hostlink config needs"),
        "fixture must reach the post-client local SSH precondition: {stderr}"
    );
    assert!(
        !stderr.contains("Cannot drop a runtime in a context where blocking is not allowed"),
        "controller operations must not create or drop a nested Tokio runtime: {stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "public access dispatch must not panic: {stderr}"
    );
}

#[test]
fn public_access_cli_leaf_help_tree_preserves_all_supported_commands() {
    // This invokes only Clap help, never Hub/SSH/Agent. It protects the public
    // command tree while ownership moves from access_cli into leaf modules.
    for (prefix, commands) in [
        (
            Vec::<&str>::new(),
            vec![
                "configure",
                "check",
                "show",
                "invite",
                "list",
                "remove",
                "info",
                "verify",
                "exec",
                "run-local",
                "run-local-evidence",
                "run-local-job",
                "job",
                "probe",
                "upload",
                "download",
                "remove-scoped",
                "rdp",
                "forward",
                "sync-ssh",
                "ssh",
            ],
        ),
        (
            vec!["job"],
            vec!["start", "status", "result", "logs", "cancel", "wait"],
        ),
        (
            vec!["run-local-job"],
            vec![
                "start",
                "status",
                "logs",
                "cancel",
                "results",
                "attest",
                "recover-attest",
                "observe-invocation",
                "recover-invocation",
                "verify-invocation-logs",
                "verify-invocation-result",
                "cleanup",
                "list-reservations",
            ],
        ),
        (vec!["run-local-evidence"], vec!["verify"]),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
            .args(&prefix)
            .arg("--help")
            .env("NO_COLOR", "1")
            .env_remove("ONEC_ACCESS_TARGET")
            .output()
            .expect("render hostlink Clap help");
        assert!(
            output.status.success(),
            "help for {prefix:?} must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "help should not log to stderr");
        let help = String::from_utf8(output.stdout).expect("help must be UTF-8");
        for command in commands {
            assert!(
                help.lines()
                    .any(|line| line.split_whitespace().next() == Some(command)),
                "{prefix:?} help lost command {command}: {help}"
            );
        }
    }

    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(["project", "--help"])
        .output()
        .expect("reject unrelated 1C domain command");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"),
        "unknown command must be rejected by Clap before any access operation"
    );
}
