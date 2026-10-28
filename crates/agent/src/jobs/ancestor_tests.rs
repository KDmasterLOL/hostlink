use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn directory_policy_rejects_foreign_writers_and_sticky_foreign_children() {
    // Exercise the production ownership predicate, not a fake filesystem API.
    // SAFETY: geteuid has no pointers or preconditions.
    let agent = unsafe { libc::geteuid() };
    let foreign = if agent == 65534 { 65533 } else { 65534 };
    for owner in [0, agent] {
        for child in [0, agent] {
            validate_source_directory_ownership(0o755, owner, Some(child)).unwrap();
            validate_source_directory_ownership(0o1777, owner, Some(child)).unwrap();
            for mode in [0o777, 0o775, 0o757] {
                assert!(validate_source_directory_ownership(mode, owner, Some(child)).is_err());
            }
        }
        assert!(validate_source_directory_ownership(0o1777, owner, Some(foreign)).is_err());
        assert!(validate_source_directory_ownership(0o1777, owner, None).is_err());
    }
    for mode in [0o755, 0o700, 0o1777] {
        assert!(validate_source_directory_ownership(mode, foreign, Some(agent)).is_err());
    }
}

#[test]
fn real_directory_modes_sticky_child_and_symlink_are_checked() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent");
    let child = parent.join("agent-child");
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let child_metadata = fs::symlink_metadata(&child).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        validate_source_directory(
            &fs::symlink_metadata(&parent).unwrap(),
            Some(&child_metadata)
        )
        .is_err()
    );
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
    validate_source_directory(
        &fs::symlink_metadata(&parent).unwrap(),
        Some(&child_metadata),
    )
    .unwrap();
    let link = temp.path().join("alias");
    std::os::unix::fs::symlink(&parent, &link).unwrap();
    assert!(
        validate_source_directory(&fs::symlink_metadata(&link).unwrap(), Some(&child_metadata))
            .is_err()
    );
    assert!(validate_source_ancestors(&link.join("agent-child")).is_err());
    assert!(validate_source_ancestors(Path::new("relative")).is_err());
}

#[test]
fn protected_home_and_sticky_tmp_require_provable_root_ownership() {
    let root = fs::symlink_metadata("/").unwrap();
    // SAFETY: geteuid has no pointers or preconditions.
    let agent = unsafe { libc::geteuid() };
    if root.uid() != 0 && root.uid() != agent {
        // A user namespace can expose an unmapped root owner. Production must
        // reject it; this is not positive proof for /home or root-owned /tmp.
        assert!(validate_source_ancestors(Path::new("/home")).is_err());
        assert_ne!(
            std::env::var("HOSTLINK_REQUIRE_NATIVE_CONTAINMENT").as_deref(),
            Ok("1"),
            "required native ancestor proof unavailable: root owner is unmapped/untrusted"
        );
        eprintln!(
            "NOT RUN: positive native ancestor walk: root owner {} is neither root nor Agent",
            root.uid()
        );
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    restrict_private_path(temp.path(), true).unwrap();
    validate_source_ancestors(temp.path()).unwrap();
    // The real root-owned sticky /tmp is allowed with our owned child, when
    // available. A private TMPDIR does not itself prove that native case.
    let tmp_metadata = fs::symlink_metadata("/tmp").unwrap();
    if tmp_metadata.uid() == 0 && tmp_metadata.mode() & 0o1777 == 0o1777 {
        let sticky = tempfile::tempdir_in("/tmp").unwrap();
        validate_source_ancestors(sticky.path()).unwrap();
    } else {
        assert_ne!(
            std::env::var("HOSTLINK_REQUIRE_NATIVE_CONTAINMENT").as_deref(),
            Ok("1"),
            "required native root-owned sticky /tmp fixture unavailable"
        );
        eprintln!("NOT RUN: native root-owned sticky /tmp fixture unavailable");
    }
    let install = std::env::current_dir().unwrap();
    validate_source_ancestors(&install).unwrap();
}
