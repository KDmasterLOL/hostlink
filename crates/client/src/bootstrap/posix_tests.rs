//! Exercise the actual target credential helpers against disposable synthetic roots.
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

fn provision(root: &Path, action: &str) -> Output {
    let script = format!(
        "set -eu\n{}\n{action}\n",
        include_str!("../../assets/github-posix.sh")
    );
    Command::new("/bin/sh")
        .args(["-c", &script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .current_dir(root)
        .output()
        .unwrap()
}

#[test]
fn target_credential_is_private_reusable_and_never_silently_replaced() {
    // The real helper rejects world-writable ancestors, including /tmp. The
    // fixture therefore lives beneath this private user's checkout, and is removed.
    use std::os::unix::fs::MetadataExt;
    let root_uid = fs::metadata("/").unwrap().uid();
    let user_uid = fs::metadata(env!("CARGO_MANIFEST_DIR")).unwrap().uid();
    if root_uid != 0 && root_uid != user_uid {
        eprintln!(
            "SKIP successful target provisioning: sandbox root owner {root_uid} violates the real helper's ancestor ownership policy"
        );
        return;
    }
    let root = tempfile::Builder::new()
        .prefix(".bootstrap-credential-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let action = "hl_provision_credential 'github_pat_synthetic_fixture_123'";
    let first = provision(root.path(), action);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stdout.is_empty());
    let credential = root.path().join("config/hostlink/credentials/github-token");
    assert_eq!(
        fs::read_to_string(&credential).unwrap(),
        "github_pat_synthetic_fixture_123"
    );
    assert_eq!(
        fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(credential.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(provision(root.path(), action).status.success());
    let different = provision(
        root.path(),
        "hl_provision_credential 'github_pat_different_synthetic'",
    );
    assert!(!different.status.success());
    assert!(!String::from_utf8_lossy(&different.stderr).contains("github_pat_"));
    assert_eq!(
        fs::read_to_string(&credential).unwrap(),
        "github_pat_synthetic_fixture_123"
    );
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(!provision(root.path(), action).status.success());
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&credential, "bad\nheader").unwrap();
    assert!(!provision(root.path(), action).status.success());
    fs::remove_file(&credential).unwrap();
    let fixture = root.path().join("other-synthetic-file");
    fs::write(&fixture, "github_pat_synthetic").unwrap();
    symlink(&fixture, &credential).unwrap();
    assert!(!provision(root.path(), action).status.success());
    assert_eq!(
        fs::read_to_string(&fixture).unwrap(),
        "github_pat_synthetic"
    );
}

#[test]
fn invalid_target_asset_is_rejected_before_credential_or_network_access() {
    let root = tempfile::tempdir().unwrap();
    for url in [
        "https://elsewhere.invalid/a",
        "https://api.github.com/repos/other/hostlink/releases/assets/1",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1?query=1",
    ] {
        let output = provision(root.path(), &format!("hl_download '{url}' '/unused' 10 1"));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("GitHub"));
        assert!(!root.path().join("config").exists());
    }
}
