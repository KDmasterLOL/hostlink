use super::*;
use crate::executable::{TEST_IMAGE_BYTES, test_image};
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
    let (_image_temp, mut image) = test_image();
    let expected = image.sha256.clone();
    publish_executable(&root, &mut image).unwrap();
    assert!(!root.join("enrollment.pending").exists());
    assert_eq!(
        fs::read(root.join("bin").join(EXECUTABLE_NAME)).unwrap(),
        TEST_IMAGE_BYTES
    );
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
    let (_retry_temp, mut retry_image) = test_image();
    assert!(publish_executable(&root, &mut retry_image).is_err());
}

#[test]
fn publication_failure_preserves_pending_and_enrollment_state_without_adoption() {
    let (_temp, root) = pending_fixture();
    let (_image_temp, mut image) = test_image();
    image.sha256 = "00".repeat(32);
    let error = publish_executable(&root, &mut image).unwrap_err();
    assert_eq!(
        error.to_string(),
        "published executable differs from the verified running image"
    );
    assert_eq!(
        fs::read(root.join("enrollment.pending")).unwrap(),
        b"keep on failure"
    );
    assert_eq!(
        fs::read(root.join("state/manifest.json")).unwrap(),
        b"private enrollment manifest"
    );
    let (_retry_temp, mut retry_image) = test_image();
    assert!(
        publish_executable(&root, &mut retry_image).is_err(),
        "a failed publication never adopts an existing bin"
    );
    assert_eq!(
        fs::read(root.join("bin").join(EXECUTABLE_NAME)).unwrap(),
        TEST_IMAGE_BYTES
    );
}

#[cfg(target_os = "linux")]
#[test]
fn executable_validation_rejects_images_larger_than_256_mib() {
    let (_temp, root) = pending_fixture();
    let (_image_temp, mut image) = test_image();
    publish_executable(&root, &mut image).unwrap();
    let path = root.join("bin").join(EXECUTABLE_NAME);
    verify_executable(&path).unwrap();
    assert_eq!(MAX_EXECUTABLE_BYTES, 256 * 1024 * 1024);
    // Linux extends this disposable file with a sparse hole; no large image is written/read.
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_EXECUTABLE_BYTES + 1)
        .unwrap();
    let error = verify_executable(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        "Agent executable is not a bounded regular file"
    );
    assert!(hash_file(&path, MAX_EXECUTABLE_BYTES).is_err());
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

#[test]
fn install_forwards_explicit_gateway_selection_to_enrollment() {
    for index in [None, Some(0), Some(2)] {
        let options = InstallOptions {
            hub_url: "https://hub.test".into(),
            token_file: "token".into(),
            name: "host".into(),
            user: "agent".into(),
            gateway_index: index,
        };
        let enrollment = enrollment_options(&options, PathBuf::from("agent"));
        assert_eq!(enrollment.gateway_index, index);
        assert!(enrollment.retain_pending);
    }
}
