//! Privacy regressions exercise the actual vendored filesystem and journal paths.

use super::private_fs::{create_private_directory, open_private_file};
use super::staging::PrivateTempDir;
use crate::update_handoff::{
    UpdateIdentity, UpdateJournal, UpdatePhase, read_journal, write_journal_atomic,
};
use private_fs::PrivateDir;
use sha2::{Digest, Sha256};
use std::fs;

fn journal() -> UpdateJournal {
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    UpdateJournal::new(UpdateIdentity {
        target: "i686-win7-windows-msvc".into(),
        old_version: "1.0.0".into(),
        old_archive_sha256: digest(b"old archive"),
        old_executable_sha256: digest(b"old executable"),
        old_metadata_sha256: digest(b"old metadata"),
        new_version: "2.0.0".into(),
        new_archive_sha256: digest(b"new archive"),
        new_executable_sha256: digest(b"new executable"),
        new_metadata_sha256: digest(b"new metadata"),
    })
    .unwrap()
}

#[test]
fn staging_and_journal_are_private_at_birth_and_phases_replace_durably() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    PrivateDir::ensure(&root).unwrap();
    let stage = PrivateTempDir::new_in(&root, ".test-").unwrap();
    create_private_directory(&stage.path().join("nested")).unwrap();
    let path = stage.path().join("handoff.json");
    let mut journal = journal();
    for phase in [
        UpdatePhase::Staged,
        UpdatePhase::BackedUp,
        UpdatePhase::Published,
    ] {
        if phase != UpdatePhase::Staged {
            journal.advance(phase).unwrap();
        }
        write_journal_atomic(&path, &journal).unwrap();
        assert_eq!(read_journal(&path).unwrap(), Some(journal.clone()));
        open_private_file(&path).unwrap().verify().unwrap();
    }
    let staged_path = stage.path().to_path_buf();
    drop(stage);
    assert!(!staged_path.exists());
}

#[test]
fn linked_journal_cannot_be_read_or_replaced_and_keeps_both_links() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    let dir = PrivateDir::ensure(&root).unwrap();
    let path = root.join("handoff.json");
    write_journal_atomic(&path, &journal()).unwrap();
    let before = fs::read(&path).unwrap();
    let alias = root.join("alias.json");
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_journal(&path).is_err());
    assert!(write_journal_atomic(&path, &journal()).is_err());
    assert!(dir.open_file("handoff.json").is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&alias).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn existing_insecure_state_and_directories_are_never_silently_hardened() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    PrivateDir::ensure(&root).unwrap();
    let path = root.join("handoff.json");
    write_journal_atomic(&path, &journal()).unwrap();
    let before = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(open_private_file(&path).is_err());
    assert!(read_journal(&path).is_err());
    assert!(write_journal_atomic(&path, &journal()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let unsafe_dir = root.join("unsafe");
    fs::create_dir(&unsafe_dir).unwrap();
    fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(create_private_directory(&unsafe_dir).is_err());
    assert!(PrivateTempDir::new_in(&unsafe_dir, ".test-").is_err());
    assert_eq!(fs::read_dir(&unsafe_dir).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(&unsafe_dir).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn extracted_executable_keeps_0700_exception_and_other_files_require_0600() {
    use super::private_fs::{file_identities, set_staged_file_permissions};
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    let dir = PrivateDir::ensure(&root).unwrap();
    for (name, mode) in [("hostlink-agent", 0o755), ("manifest.json", 0o644)] {
        dir.create(name).unwrap();
        let path = root.join(name);
        fs::write(&path, b"extracted bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        set_staged_file_permissions(&path, name).unwrap();
    }
    let exe = root.join("hostlink-agent");
    assert_eq!(
        fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(dir.open_file("hostlink-agent").is_err());
    assert!(file_identities(&root, &["hostlink-agent".into()]).is_ok());
    dir.open_file("manifest.json").unwrap().verify().unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(file_identities(&root, &["hostlink-agent".into()]).is_err());
}

#[cfg(unix)]
#[test]
fn journal_rejects_symlinked_parent_without_touching_target() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    PrivateDir::ensure(&root).unwrap();
    let path = root.join("handoff.json");
    write_journal_atomic(&path, &journal()).unwrap();
    let before = fs::read(&path).unwrap();
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(read_journal(&alias.join("handoff.json")).is_err());
    assert!(write_journal_atomic(&alias.join("handoff.json"), &journal()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}
