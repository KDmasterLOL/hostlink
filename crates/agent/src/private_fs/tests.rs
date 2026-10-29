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
    let sddl = format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", owner.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().unwrap();
    SetNamedSecurityInfo(
        file.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .unwrap();
    let metadata = fs::symlink_metadata(&file).unwrap();
    windows::validate_acl(
        &file,
        &metadata,
        windows::AllowedPrincipals::OwnerSystemAdministrators,
        true,
    )
    .unwrap();
    assert!(
        windows::validate_acl(
            &file,
            &metadata,
            windows::AllowedPrincipals::OwnerOnly,
            true,
        )
        .is_err()
    );
}
