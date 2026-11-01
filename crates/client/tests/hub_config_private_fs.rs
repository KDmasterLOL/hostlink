#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

fn configure(config_path: &Path, token_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .env("HOSTLINK_HUB_CONFIG", config_path)
        .args([
            "hub",
            "configure",
            "--hub-url",
            "https://hub.example.invalid",
            "--token-file",
        ])
        .arg(token_path)
        .args([
            "--ssh-user",
            "hostlink",
            "--identity",
            "/nonexistent/controller.key",
            "--gateway-identity",
            "/nonexistent/gateway.key",
        ])
        .output()
        .expect("run disposable Hub config CLI")
}

fn show(config_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .env("HOSTLINK_HUB_CONFIG", config_path)
        .args(["hub", "show"])
        .output()
        .expect("run offline Hub show")
}

fn external_token(root: &Path) -> std::path::PathBuf {
    let token = root.join("operator.token");
    fs::write(&token, b"synthetic-private-token-not-real").unwrap();
    // This user-provided input intentionally retains the existing 0400 policy.
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    token
}

#[test]
fn configure_creates_private_atomic_config_without_changing_external_token() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("HostLink/hub.json");
    let token = external_token(root.path());

    let created = configure(&config, &token);
    assert!(
        created.status.success(),
        "configure: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert_eq!(
        fs::metadata(config.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&token).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let original = fs::read(&config).unwrap();

    let duplicate = configure(&config, &token);
    assert!(!duplicate.status.success(), "create-new must not overwrite");
    assert_eq!(fs::read(&config).unwrap(), original);
    assert!(!String::from_utf8_lossy(&duplicate.stderr).contains("synthetic-private-token"));

    fs::remove_file(&token).unwrap();
    let offline = show(&config);
    assert!(
        offline.status.success(),
        "hub show must not require external token: {}",
        String::from_utf8_lossy(&offline.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&offline.stdout).unwrap();
    assert_eq!(parsed["hub_url"], "https://hub.example.invalid");
}

#[test]
fn configure_rejects_insecure_or_linked_managed_root_without_healing_it() {
    let root = tempfile::tempdir().unwrap();
    let token = external_token(root.path());

    let public_dir = root.path().join("public-hostlink");
    fs::create_dir(&public_dir).unwrap();
    fs::set_permissions(&public_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let config = public_dir.join("hub.json");
    assert!(!configure(&config, &token).status.success());
    assert!(!config.exists());
    assert_eq!(
        fs::metadata(&public_dir).unwrap().permissions().mode() & 0o777,
        0o755,
        "existing untrusted root must never be chmod'ed"
    );

    let private_dir = root.path().join("real-hostlink");
    fs::create_dir(&private_dir).unwrap();
    fs::set_permissions(&private_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("symlink-hostlink");
    symlink(&private_dir, &alias).unwrap();
    assert!(!configure(&alias.join("hub.json"), &token).status.success());
    assert!(!private_dir.join("hub.json").exists());
}

#[test]
fn offline_show_rejects_noncanonical_managed_permissions() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("HostLink/hub.json");
    let token = external_token(root.path());
    assert!(configure(&config, &token).status.success());

    fs::set_permissions(&config, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(
        !show(&config).status.success(),
        "managed 0400 is noncanonical"
    );
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(show(&config).status.success());
}
