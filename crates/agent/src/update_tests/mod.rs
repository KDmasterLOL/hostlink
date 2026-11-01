use super::*;
use std::fs;

mod credentials;
mod fixture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod github_http;
use fixture::Fixture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use fixture::{digest, package};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(windows, target_arch = "x86_64"))]
const TARGET: &str = "x86_64-win7-windows-msvc";
#[cfg(all(windows, target_arch = "x86"))]
const TARGET: &str = "i686-win7-windows-msvc";

#[cfg(target_os = "linux")]
#[test]
fn unknown_development_binary_does_not_guess_an_installed_root() {
    assert!(default_update_root().is_err());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn private_locks_aliases_and_installed_integrity_fail_before_network() {
    let fixture = Fixture::new();
    let apply = |root: &Path| {
        apply_update(
            root,
            None,
            Update::configure(),
            Arc::new(GitHubTransport::new(true)),
        )
    };
    for name in ["update.lock", "jobs/runner.lock"] {
        let lock = PrivateDir::open(&fixture.root)
            .unwrap()
            .open_file_with(
                name,
                OpenOptions {
                    access: FileAccess::ReadWrite,
                    creation: FileCreation::OpenOrCreate,
                    ..OpenOptions::default()
                },
            )
            .unwrap()
            .try_clone_std()
            .unwrap();
        lock.try_lock().unwrap();
        assert_eq!(
            apply(&fixture.root).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(fixture.root.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
    assert!(apply(&alias).is_err());
    fs::write(fixture.root.join("bin/hostlink-agent"), b"tampered").unwrap();
    assert!(apply(&fixture.root).is_err());
}

#[test]
fn publication_guard_rejects_unpublished_unstable_malformed_and_large_metadata() {
    let metadata = |tag: &str, draft: bool, prerelease: bool| {
        serde_json::to_vec(&serde_json::json!({
            "tag_name": tag, "draft": draft, "prerelease": prerelease
        }))
        .unwrap()
    };
    for tag in ["1.2.3", "v1.2.3"] {
        assert_eq!(
            validate_github_metadata(&metadata(tag, false, false), true)
                .unwrap()
                .tag_name,
            tag
        );
        assert!(validate_github_metadata(&metadata(tag, true, false), false).is_err());
        assert!(validate_github_metadata(&metadata(tag, false, true), true).is_err());
    }
    for tag in ["vv1.2.3", "release-1.2.3", "1.2", "", "1.2.3\n"] {
        assert!(validate_github_metadata(&metadata(tag, false, false), false).is_err());
    }
    let prerelease = metadata("v2.0.0-beta.1", false, false);
    assert!(validate_github_metadata(&prerelease, true).is_err());
    assert!(validate_github_metadata(&prerelease, false).is_ok());
    for body in [b"{}".as_slice(), b"[]", b"null", b"not JSON"] {
        assert!(validate_github_metadata(body, true).is_err());
    }
    assert!(validate_github_metadata(&vec![b' '; MAX_METADATA_BYTES as usize + 1], false).is_err());
}

#[test]
fn installed_and_archive_integrity_checks_fail_closed() {
    for name in [
        PACKAGE_MANIFEST,
        ARCHIVE_DIGEST,
        if TARGET.contains("windows") {
            "hostlink-agent.exe"
        } else {
            EXECUTABLE_BASE
        },
    ] {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("bin").join(name), b"tampered").unwrap();
        assert!(read_installed(&fixture.root).is_err());
    }
    let fixture = Fixture::new();
    let archive = fixture.temp.path().join("oversized.zip");
    File::create(&archive)
        .unwrap()
        .set_len(MAX_ARCHIVE_BYTES + 1)
        .unwrap();
    assert!(validate_contents(&archive, TARGET, "2.0.0").is_err());
}
