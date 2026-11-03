use super::*;

#[test]
fn canonical_windows_volume_root_is_checked_after_prefix() {
    let folder = tempfile::tempdir().unwrap();
    let canonical = folder.path().canonicalize().unwrap();
    assert!(matches!(
        canonical.components().next(),
        Some(Component::Prefix(_))
    ));
    validate_path_has_no_reparse_components(&canonical).unwrap();
    assert!(matches!(
        fs::symlink_metadata(canonical.join("not-created"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    ));
}
