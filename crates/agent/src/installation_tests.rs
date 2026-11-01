use super::*;
use std::io::Write;

#[cfg(target_os = "linux")]
#[test]
fn stable_data_root_uses_absolute_xdg_then_home() {
    let home = Some(Path::new("/disposable/home"));
    for xdg in [None, Some(Path::new("")), Some(Path::new("relative/data"))] {
        assert_eq!(
            root_from_data(xdg, home).unwrap(),
            Path::new("/disposable/home/.local/share/hostlink/Agent")
        );
    }
    assert_eq!(
        root_from_data(Some(Path::new("/disposable/data")), None).unwrap(),
        Path::new("/disposable/data/hostlink/Agent")
    );
    assert!(root_from_data(None, None).is_err());
    assert!(root_from_data(None, Some(Path::new("relative/home"))).is_err());
    assert!(root_from_data(Some(Path::new("/disposable/../data")), home).is_err());
}

fn pending_fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("Agent");
    let dir = PrivateDir::ensure(&root).unwrap();
    dir.create("enrollment.pending")
        .unwrap()
        .write_all(b"keep on failure")
        .unwrap();
    let state = dir.create_dir("state").unwrap();
    state
        .create("manifest.json")
        .unwrap()
        .write_all(b"private enrollment manifest")
        .unwrap();
    (temp, root)
}

#[test]
fn publication_copies_running_image_and_keeps_only_binary_plus_enrollment_state() {
    let (_temp, root) = pending_fixture();
    let mut image = RunningExecutable::open().unwrap();
    let expected = image.sha256.clone();
    publish_executable(&root, &mut image).unwrap();
    assert!(!root.join("enrollment.pending").exists());
    assert_eq!(
        hash_file(
            &root.join("bin").join(EXECUTABLE_NAME),
            MAX_EXECUTABLE_BYTES
        )
        .unwrap(),
        expected
    );
    assert_eq!(fs::read_dir(root.join("bin")).unwrap().count(), 1);
    assert_eq!(
        fs::read(root.join("state/manifest.json")).unwrap(),
        b"private enrollment manifest"
    );
    assert!(!root.join("bootstrap-receipt.json").exists());
    assert!(!root.join("bin/manifest.json").exists());
    assert!(!root.join("bin/archive.sha256").exists());
    assert!(publish_executable(&root, &mut RunningExecutable::open().unwrap()).is_err());
}

#[test]
fn publication_failure_preserves_pending_and_enrollment_state_without_adoption() {
    let (_temp, root) = pending_fixture();
    let mut image = RunningExecutable::open().unwrap();
    image.sha256 = "00".repeat(32);
    assert!(publish_executable(&root, &mut image).is_err());
    assert!(root.join("enrollment.pending").is_file());
    assert_eq!(
        fs::read(root.join("state/manifest.json")).unwrap(),
        b"private enrollment manifest"
    );
    assert!(
        publish_executable(&root, &mut RunningExecutable::open().unwrap()).is_err(),
        "a failed publication never adopts an existing bin"
    );
}

#[cfg(unix)]
#[test]
fn unsafe_ancestor_is_rejected_without_creating_an_installation() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(temp.path(), &alias).unwrap();
    assert!(ensure_parent(&alias.join("hostlink")).is_err());
    assert!(!temp.path().join("hostlink").exists());
}
