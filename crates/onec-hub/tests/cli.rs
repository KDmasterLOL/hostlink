use std::process::Command;

#[test]
fn hostlink_hub_binary_name_and_help_are_available_without_state_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_hostlink-hub"))
        .arg("--help")
        .output()
        .expect("run HostLink Hub help");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("help UTF-8");
    assert!(help.contains("\nUsage: hostlink-hub "), "{help}");
    assert!(
        help.contains("HostLink enrollment and discovery hub"),
        "{help}"
    );
}
