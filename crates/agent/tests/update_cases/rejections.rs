use super::*;

#[test]
fn wrong_digest_and_wrong_target_fail_before_publication() {
    let (_temp, root) = install_root();
    let (archive, _) = package(&root, "2.0.0", b"new exact Agent binary");
    let before = fs::read(root.join("bin/hostlink-agent")).expect("old binary");
    let bad_digest = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&bad_digest).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary remains"),
        before
    );

    let mut wrong_target = request(&root, &archive, "2.0.0", "0".repeat(64));
    wrong_target.target = "i686-win7-windows-msvc".to_owned();
    assert!(apply_empty_jobs(&wrong_target).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary remains"),
        before
    );
}

#[cfg(unix)]
#[test]
fn symlinked_archive_is_rejected_without_changes() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = install_root();
    let (outside_temp, outside_root) = install_root();
    let (outside, digest) = package(&outside_root, "2.0.0", b"new exact Agent binary");
    let linked = root.join("linked.zip");
    symlink(outside, &linked).expect("archive symlink");
    let request = request(&root, &linked, "2.0.0", digest);
    assert!(apply_empty_jobs(&request).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary"),
        b"old installed Agent binary"
    );
    drop(outside_temp);
}
#[cfg(unix)]
#[test]
fn archive_with_symlinked_parent_inside_install_root_is_rejected() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let archive_dir = root.join("archives");
    private_fs::PrivateDir::open(&root)
        .unwrap()
        .create_dir("archives")
        .unwrap();
    let relocated = archive_dir.join("package.zip");
    fs::rename(&archive, &relocated).unwrap();
    let alias = root.join("archive-alias");
    symlink(&archive_dir, &alias).unwrap();

    let update = request(&root, &alias.join("package.zip"), "2.0.0", digest);
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).unwrap(),
        b"old installed Agent binary"
    );
}

#[test]
fn archive_manifest_must_bind_exact_version_and_target() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let mut request = request(&root, &archive, "2.1.0", digest);
    assert!(apply_empty_jobs(&request).is_err());
    request.version = "invalid".to_owned();
    assert!(apply_empty_jobs(&request).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary"),
        b"old installed Agent binary"
    );
}
#[test]
fn zip_slip_and_symlink_members_are_rejected() {
    let (_temp, root) = install_root();
    for (member, symlink) in [("../escape", false), ("hostlink-agent", true)] {
        let (archive, digest) = malicious_archive(&root, member, symlink);
        let update = request(&root, &archive, "2.0.0", digest);
        assert!(apply_empty_jobs(&update).is_err());
        assert_eq!(
            fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
            b"old installed Agent binary"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinked_install_root_is_rejected() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let alias = root.with_file_name("Agent-alias");
    symlink(&root, &alias).expect("install root symlink");
    let update = request(&alias, &archive, "2.0.0", digest);
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}
#[test]
fn oversized_archive_is_rejected_before_copy_or_publication() {
    let (_temp, root) = install_root();
    let archive = root.join("oversized.zip");
    let file = File::create(&archive).expect("sparse oversized archive");
    file.set_len(512 * 1024 * 1024 + 1)
        .expect("set oversized archive length");
    let update = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}
