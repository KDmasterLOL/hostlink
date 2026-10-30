use super::*;

#[test]
fn private_paths_reject_links_and_non_private_modes() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let file = root.path().join("file");
    fs::write(&file, b"contents").unwrap();
    restrict_private_path(&file, false).unwrap();
    validate_private_path(&file, false).unwrap();
    assert!(validate_private_path(&file, true).is_err());
    assert!(validate_private_path(root.path(), false).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let link = root.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(validate_private_path(&link, false).is_err());

        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_private_path(&file, false).is_err());
        restrict_private_path(&file, false).unwrap();

        let second = root.path().join("second");
        fs::hard_link(&file, &second).unwrap();
        assert!(validate_private_path(&file, false).is_err());
    }
}

#[test]
fn std_file_lock_serializes_independent_handles() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let path = root.path().join("update.lock");
    let first = open_lock(&path).unwrap();
    first.lock().unwrap();
    let second = open_lock(&path).unwrap();
    assert!(second.try_lock().is_err());
    first.unlock().unwrap();
    second.try_lock().unwrap();
    second.unlock().unwrap();
}

#[cfg(windows)]
#[test]
fn windows_acl_preserves_different_agent_policies() {
    use windows_permissions::{
        LocalBox, SecurityDescriptor,
        constants::{SeObjectType, SecurityInformation},
        wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo},
    };
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let file = root.path().join("acl");
    fs::write(&file, b"private").unwrap();
    restrict_private_path(&file, false).unwrap();

    let owner = windows_permissions::utilities::current_process_sid().unwrap();
    let owner = ConvertSidToStringSid(&owner).unwrap();
    for (suffix, protected, owner_only, shared) in [
        ("", true, true, true),
        ("(A;;FA;;;SY)", true, false, true),
        ("(A;;FA;;;BA)", true, false, true),
        ("(A;;FR;;;WD)", true, false, false),
        ("", false, false, false),
    ] {
        let sddl = format!("D:(A;;FA;;;{}){suffix}", owner.to_string_lossy());
        let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().unwrap();
        let protection = if protected {
            SecurityInformation::ProtectedDacl
        } else {
            SecurityInformation::UnprotectedDacl
        };
        SetNamedSecurityInfo(
            file.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | protection,
            None,
            None,
            descriptor.dacl(),
            None,
        )
        .unwrap();
        for (policy, expected) in [
            (windows::AllowedPrincipals::OwnerOnly, owner_only),
            (
                windows::AllowedPrincipals::OwnerSystemAdministrators,
                shared,
            ),
        ] {
            assert_eq!(windows::validate_acl(&file, policy, true).is_ok(), expected);
        }
        assert_eq!(open_lock(&file).is_ok(), shared);
    }
}

#[test]
fn lock_reopen_preserves_contents_and_rejects_hardlinks() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let path = root.path().join("runner.lock");
    let mut first = open_lock(&path).unwrap();
    std::io::Write::write_all(&mut first, b"preserve").unwrap();
    drop(first);
    drop(open_lock(&path).unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
    fs::hard_link(&path, root.path().join("alias")).unwrap();
    assert!(open_lock(&path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(restrict_private_path(&path, false).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
    #[cfg(windows)]
    assert!(restrict_private_path(&path, false).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
}

#[cfg(unix)]
#[test]
fn hardening_and_lock_open_never_chmod_link_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    fs::write(&target, b"unchanged").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    let link = root.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(restrict_private_path(&link, false).is_err());
    assert!(open_lock(&link).is_err());
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");

    let directory = root.path().join("directory");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(restrict_private_path(&directory.join(".."), true).is_err());
    let link = root.path().join("directory-link");
    symlink(&directory, &link).unwrap();
    for alias in [link.clone(), link.join(""), link.join(".")] {
        assert!(restrict_private_path(&alias, true).is_err());
    }
    let nested = directory.join("file");
    fs::write(&nested, b"private ancestor target").unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(restrict_private_path(&link.join("file"), false).is_err());
    assert!(validate_private_path(&link.join("file"), false).is_err());
    assert_eq!(
        fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn lock_rejects_insecure_files_parents_and_parent_aliases() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("update.lock");
    fs::write(&path, b"contents").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(open_lock(&path).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    restrict_private_path(&path, false).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(open_lock(&path).is_err());
    assert!(open_lock(&root.path().join("new.lock")).is_err());
    assert!(!root.path().join("new.lock").exists());
    restrict_private_path(root.path(), true).unwrap();
    let link = root.path().join("alias");
    symlink(root.path(), &link).unwrap();
    assert!(open_lock(&link.join("update.lock")).is_err());
}
