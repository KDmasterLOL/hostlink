#![cfg(target_os = "linux")]

use private_fs::PrivateDir;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn copy_executable(source: &Path, destination: &Path) {
    // Keep the writable descriptor out of this process: a concurrent fork
    // could inherit it until exec and cause ETXTBSY.
    let copy = Command::new("cp")
        .arg(source)
        .arg(destination)
        .status()
        .expect("start fixture binary copy");
    assert!(copy.success(), "fixture binary copy failed: {copy}");
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let staging = temp.path().join("staging-agent");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_hostlink-agent")), &staging);
    (temp, staging)
}

fn command(temp: &Path, executable: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .env("HOME", temp)
        .env("XDG_DATA_HOME", temp.join("data"))
        .env("XDG_CONFIG_HOME", temp.join("config"))
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN");
    command
}

fn error(output: Output) -> String {
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

fn private_root(temp: &Path) -> PathBuf {
    let data = PrivateDir::ensure(temp.join("data")).unwrap();
    let owner = data.create_dir("hostlink").unwrap();
    owner.create_dir("Agent").unwrap();
    temp.join("data/hostlink/Agent")
}

fn install_command(temp: &Path, executable: &Path) -> Command {
    let mut command = command(temp, executable);
    command
        .args([
            "install",
            "--hub-url",
            "https://127.0.0.1:9",
            "--token-file",
        ])
        .arg(temp.join("invite-token"))
        .args(["--name", "fixture", "--user", "agent"]);
    command
}

#[test]
fn cli_reports_its_own_exact_build_identity_without_credentials() {
    let (temp, executable) = fixture();
    let output = command(temp.path(), &executable)
        .arg("binary-info")
        .output()
        .unwrap();
    assert!(output.status.success());
    let identity: hostlink_agent::installation::BinaryIdentity =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        identity,
        hostlink_agent::installation::current_binary_identity()
    );
}

#[test]
fn cli_install_refuses_an_existing_stable_root_without_adopting_it() {
    let (temp, executable) = fixture();
    let root = private_root(temp.path());
    fs::write(root.join("unknown"), b"preserve").unwrap();
    assert!(
        error(install_command(temp.path(), &executable).output().unwrap())
            .contains("already exists")
    );
    assert_eq!(fs::read(root.join("unknown")).unwrap(), b"preserve");
    assert!(!root.join("enrollment.pending").exists());
    let diagnostic = error(
        install_command(temp.path(), &executable)
            .args(["--machine-id", "other-id"])
            .output()
            .unwrap(),
    );
    assert!(
        diagnostic.contains("No such file") || diagnostic.contains("damaged"),
        "{diagnostic}"
    );
    assert!(
        !root.join("update.lock").exists(),
        "a foreign root must not acquire installer files"
    );
}

#[test]
fn cli_repair_never_initializes_a_missing_root_or_accepts_unbound_rotation() {
    let (temp, executable) = fixture();
    let diagnostic = error(
        install_command(temp.path(), &executable)
            .args(["--machine-id", "expected-id"])
            .output()
            .unwrap(),
    );
    assert!(diagnostic.contains("requires the existing installation"));
    assert!(!temp.path().join("data/hostlink/Agent").exists());
    let output = install_command(temp.path(), &executable)
        .arg("--replace-identity")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn cli_pending_repair_blocks_offline_launch_update_and_service_start() {
    let (temp, executable) = fixture();
    let root = private_root(temp.path());
    let dir = PrivateDir::open(&root).unwrap();
    dir.create("repair.pending")
        .unwrap()
        .write_all(b"reconcile")
        .unwrap();
    dir.create_dir("jobs").unwrap();
    let state = dir.create_dir("state").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    state.create("agent.json").unwrap().write_all(serde_json::json!({
        "listen": address, "user":"agent", "host_key":"missing-host-key", "authorized_keys":"missing-controller-keys",
        "jobs_root": root.join("jobs"), "gateway":null
    }).to_string().as_bytes()).unwrap();
    let diagnostic = error(
        command(temp.path(), &executable)
            .args(["run", "--config"])
            .arg(root.join("state/agent.json"))
            .output()
            .unwrap(),
    );
    assert!(diagnostic.contains("transaction pending"), "{diagnostic}");
    assert!(!root.join("jobs/jobs.db").exists());
    let diagnostic = error(
        command(temp.path(), &executable)
            .args(["service", "start", "--root"])
            .arg(&root)
            .output()
            .unwrap(),
    );
    assert!(diagnostic.contains("transaction pending"), "{diagnostic}");
    let diagnostic = error(
        command(temp.path(), &executable)
            .args(["update", "--root"])
            .arg(&root)
            .output()
            .unwrap(),
    );
    assert!(diagnostic.contains("transaction pending"), "{diagnostic}");
}

#[test]
fn cli_uncertain_install_preserves_pending_and_never_installs_scripts_or_commands() {
    let (temp, executable) = fixture();
    let mut token = PrivateDir::open(temp.path())
        .unwrap()
        .create("invite-token")
        .unwrap();
    token
        .write_all("0123456789abcdef".repeat(4).as_bytes())
        .unwrap();
    drop(token);
    let diagnostic = error(install_command(temp.path(), &executable).output().unwrap());
    assert!(
        diagnostic.contains("pending reconciliation"),
        "{diagnostic}"
    );
    let root = temp.path().join("data/hostlink/Agent");
    assert!(root.join("enrollment.pending").is_file());
    assert!(!root.join("bin").exists());
    assert!(!root.join("bootstrap-receipt.json").exists());
    assert!(
        error(install_command(temp.path(), &executable).output().unwrap())
            .contains("transaction pending")
    );
}

#[test]
fn cli_update_checks_root_and_installed_image_before_release_network_io() {
    let (temp, executable) = fixture();
    let root = private_root(temp.path());
    let dir = PrivateDir::open(&root).unwrap();
    dir.create_dir("jobs").unwrap();
    dir.create_dir("bin").unwrap();
    copy_executable(&executable, &root.join("bin/hostlink-agent"));
    let alternate = temp.path().join("other-Agent");
    let diagnostic = error(
        command(temp.path(), &executable)
            .arg("update")
            .arg("--root")
            .arg(&alternate)
            .output()
            .unwrap(),
    );
    assert!(diagnostic.contains("stable current-user"), "{diagnostic}");
    assert!(!alternate.exists());
    // A corrupt installed image must fail locally before any public GitHub
    // release discovery, including on completely offline machines.
    fs::write(root.join("bin/hostlink-agent"), b"").unwrap();
    let diagnostic = error(
        command(temp.path(), &executable)
            .arg("update")
            .output()
            .unwrap(),
    );
    assert!(
        diagnostic.contains("Agent executable is not a bounded regular file"),
        "{diagnostic}"
    );
    assert!(!temp.path().join("config").exists());
}
