use std::process::Command;

fn hostlink(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args(args)
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
    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .env_remove("HOME")
        .args([
            "check",
            "--config",
            "/definitely-missing-hostlink-fixture.json",
        ])
        .output()
        .expect("start hostlink CLI without HOME");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file or directory"),
        "explicit --config must read that file rather than requiring HOME: {stderr}"
    );
}

#[test]
fn forwarding_probe_and_rdp_accept_exactly_one_host_selection() {
    let commands: &[&[&str]] = &[
        &[
            "forward",
            "--listen",
            "127.0.0.1:13389",
            "--target",
            "127.0.0.1:3389",
        ],
        &["rdp"],
        &["probe", "--target", "127.0.0.1:443"],
    ];
    for command in commands {
        let mut selected = command.to_vec();
        selected.extend(["--host", "lab-win7"]);
        let output = hostlink(&selected);
        assert!(
            !output.status.success(),
            "there is no configured Hub fixture"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument") && !stderr.contains("required arguments"),
            "named host selector was rejected by the CLI: {stderr}"
        );

        let mut both = command.to_vec();
        both.extend(["--host", "lab-win7", "--config", "host.json"]);
        let output = hostlink(&both);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "both host selection methods must be rejected"
        );

        let output = hostlink(command);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("required"),
            "missing host selector must be rejected"
        );
    }
}
