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
