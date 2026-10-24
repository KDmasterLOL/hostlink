use std::{fs, process::Command};
use tempfile::tempdir;

const HOSTLINK: &str = env!("CARGO_BIN_EXE_hostlink");

fn run_local(args: &[&str], config_path: &std::path::Path) -> std::process::Output {
    Command::new(HOSTLINK)
        .args(["run-local"])
        .args(args)
        .env("ONEC_ACCESS_CONFIG", config_path)
        .env_remove("ONEC_ACCESS_TARGET")
        .output()
        .expect("run hostlink run-local")
}

fn assert_failure_is_stderr_only(output: &std::process::Output) -> String {
    assert!(
        !output.status.success(),
        "failure must have a nonzero exit code"
    );
    assert!(
        output.stdout.is_empty(),
        "runner diagnostics must not pollute stdout"
    );
    String::from_utf8(output.stderr.clone()).expect("stderr UTF-8")
}

#[test]
fn runner_accepts_explicit_target_effect_mapping_and_libtest_argv() {
    let dir = tempdir().expect("owned runner fixtures");
    let candidate = dir.path().join("native-test.exe");
    let mapped = dir.path().join("suite.json");
    let config = dir.path().join("missing-controller.json");
    fs::write(&candidate, b"owned candidate fixture").expect("candidate fixture");
    fs::write(&mapped, b"owned mapped fixture").expect("mapped fixture");

    let output = Command::new(HOSTLINK)
        .args([
            "run-local",
            "--target",
            "runner-contract-unresolved-target",
            "--required-effect",
            "disposable",
            "--map-file-env",
            "NEXTEST_BIN_EXE_onec",
            "--",
            candidate.to_str().expect("candidate path UTF-8"),
            "--list",
        ])
        .env("ONEC_ACCESS_CONFIG", &config)
        .env_remove("ONEC_ACCESS_TARGET")
        .env("NEXTEST_BIN_EXE_onec", &mapped)
        .output()
        .expect("run hostlink with mapped test asset");
    let stderr = assert_failure_is_stderr_only(&output);

    // All local syntax, mapped-file and trailing-argv validation was accepted.
    // This owned-fixture test intentionally stops before creating a Hub/Agent.
    assert!(
        stderr.contains("configure access before using remote operations"),
        "expected the deliberate no-controller boundary, got: {stderr}"
    );
}

#[test]
fn runner_requires_target_and_effect_before_any_remote_attempt() {
    let dir = tempdir().expect("owned runner fixtures");
    let candidate = dir.path().join("candidate.exe");
    fs::write(&candidate, b"owned candidate fixture").expect("candidate fixture");
    let config = dir.path().join("missing-controller.json");

    let missing_target = run_local(
        &[
            "--required-effect",
            "read-only",
            "--",
            candidate.to_str().expect("candidate path UTF-8"),
            "--list",
        ],
        &config,
    );
    let stderr = assert_failure_is_stderr_only(&missing_target);
    assert!(
        stderr.contains("run-local requires --target or ONEC_ACCESS_TARGET"),
        "{stderr}"
    );

    let missing_effect = run_local(
        &[
            "--target",
            "runner-contract-target",
            "--",
            candidate.to_str().expect("candidate path UTF-8"),
            "--list",
        ],
        &config,
    );
    let stderr = assert_failure_is_stderr_only(&missing_effect);
    assert!(stderr.contains("--required-effect"), "{stderr}");
}

#[test]
fn runner_rejects_missing_candidate_and_unset_mapped_environment() {
    let dir = tempdir().expect("owned runner fixtures");
    let config = dir.path().join("missing-controller.json");
    let absent = dir.path().join("absent.exe");
    let output = run_local(
        &[
            "--target",
            "runner-contract-target",
            "--required-effect",
            "read-only",
            "--",
            absent.to_str().expect("candidate path UTF-8"),
            "--list",
        ],
        &config,
    );
    let stderr = assert_failure_is_stderr_only(&output);
    assert!(stderr.contains("cannot inspect local file"), "{stderr}");

    let candidate = dir.path().join("candidate.exe");
    fs::write(&candidate, b"owned candidate fixture").expect("candidate fixture");
    let output = Command::new(HOSTLINK)
        .args([
            "run-local",
            "--target",
            "runner-contract-target",
            "--required-effect",
            "read-only",
            "--map-file-env",
            "NEXTEST_BIN_EXE_missing",
            "--",
        ])
        .arg(&candidate)
        .arg("--list")
        .env("ONEC_ACCESS_CONFIG", &config)
        .env_remove("ONEC_ACCESS_TARGET")
        .env_remove("NEXTEST_BIN_EXE_missing")
        .output()
        .expect("run hostlink mapped-environment validation");
    let stderr = assert_failure_is_stderr_only(&output);
    assert!(
        stderr.contains("source environment variable \"NEXTEST_BIN_EXE_missing\" is not set"),
        "{stderr}"
    );

    let output = Command::new(HOSTLINK)
        .args([
            "run-local",
            "--target",
            "runner-contract-target",
            "--required-effect",
            "read-only",
            "--map-file-env",
            "",
            "--",
        ])
        .arg(&candidate)
        .arg("--list")
        .env("ONEC_ACCESS_CONFIG", &config)
        .env_remove("ONEC_ACCESS_TARGET")
        .output()
        .expect("run hostlink mapped-environment name validation");
    let stderr = assert_failure_is_stderr_only(&output);
    assert!(
        stderr.contains("invalid environment variable name \"\""),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn runner_rejects_symlink_candidates() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("owned runner fixtures");
    let target = dir.path().join("real-candidate.exe");
    let link = dir.path().join("candidate-link.exe");
    fs::write(&target, b"owned candidate fixture").expect("candidate fixture");
    symlink(&target, &link).expect("candidate symlink");

    let output = run_local(
        &[
            "--target",
            "runner-contract-target",
            "--required-effect",
            "read-only",
            "--",
            link.to_str().expect("candidate path UTF-8"),
            "--list",
        ],
        &dir.path().join("missing-controller.json"),
    );
    let stderr = assert_failure_is_stderr_only(&output);
    assert!(stderr.contains("is not a regular file"), "{stderr}");
}

#[test]
fn run_local_help_keeps_the_external_runner_flags_and_command_shape() {
    let output = Command::new(HOSTLINK)
        .args(["run-local", "--help"])
        .output()
        .expect("render run-local help");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("help UTF-8");
    for fragment in [
        "Usage: hostlink run-local",
        "--target",
        "--required-effect",
        "--map-file-env",
        "<COMMAND>...",
    ] {
        assert!(help.contains(fragment), "help lost {fragment:?}: {help}");
    }
}
