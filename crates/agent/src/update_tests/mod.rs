use super::*;
use std::fs;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::io;

mod fixture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod http;
use fixture::{Fixture, digest, package};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(windows, target_arch = "x86_64"))]
const TARGET: &str = "x86_64-win7-windows-msvc";
#[cfg(all(windows, target_arch = "x86"))]
const TARGET: &str = "i686-win7-windows-msvc";

#[test]
fn selected_source_requires_exact_https_version_target_and_digest() {
    let fixture = Fixture::new();
    let url = format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip");
    let digest = digest(b"independent artifact");
    for bad in [
        url.replace("https:", "http:"),
        url.replace("/v2.0.0/", "/v3.0.0/"),
        url.replace("artifacts.example", "user@artifacts.example"),
        format!("{url}#fragment"),
        url.replace("/v2.0.0/", "/%2e%2e/v2.0.0/"),
        url.replace("/v2.0.0/", "/v2.0.0/../v2.0.0/"),
    ] {
        assert!(update(&fixture.root, &bad, &digest, TARGET, "2.0.0").is_err());
    }
    assert!(update(&fixture.root, &url, "bad digest", TARGET, "2.0.0").is_err());
    assert!(update(&fixture.root, &url, &digest, "unsupported", "2.0.0").is_err());
    assert!(update(&fixture.root, &url, &digest, TARGET, "not-semver").is_err());

    let release = Release::builder()
        .version("2.0.0")
        .asset(ReleaseAsset::new(
            format!("hostlink-agent-{TARGET}.zip"),
            &url,
        ))
        .build()
        .unwrap();
    let selected = SelectedRelease(release);
    assert!(selected.get_release_version("2.0.1").is_err());
    assert_eq!(
        selected.get_release_version("2.0.0").unwrap().assets()[0].download_url(),
        url
    );
}

#[test]
fn installed_bundle_retains_verbatim_manifest_and_pinned_archive_digest() {
    let fixture = Fixture::new();
    let body = package("2.0.0", b"new executable", false);
    let archive = fixture.temp.path().join("new.zip");
    fs::write(&archive, &body).unwrap();
    let (_, bytes) = crate::package::validate_contents(&archive, TARGET, "2.0.0").unwrap();
    let staging = fixture.temp.path().join("stage");
    self_update::Extract::from_source(&archive)
        .extract_into(&staging)
        .unwrap();
    let bundle = staging.join(format!("hostlink-agent-{TARGET}"));
    fs::write(bundle.join(ARCHIVE_DIGEST), digest(&body)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let exe = bundle.join(EXECUTABLE_BASE);
        fs::set_permissions(exe, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let manifest: PackageManifest =
        serde_json::from_slice(&fs::read(bundle.join(PACKAGE_MANIFEST)).unwrap()).unwrap();
    assert_eq!(fs::read(bundle.join(PACKAGE_MANIFEST)).unwrap(), bytes);
    validate_installed(&bundle, &manifest, TARGET).unwrap();

    fs::rename(fixture.root.join("bin"), fixture.root.join("old-bin")).unwrap();
    fs::rename(bundle, fixture.root.join("bin")).unwrap();
    let (installed, archive_digest) = read_installed(&fixture.root).unwrap();
    assert_eq!(installed.version, "2.0.0");
    assert_eq!(archive_digest, digest(&body));

    fs::write(fixture.root.join("bin/archive.sha256"), b"invalid").unwrap();
    assert!(read_installed(&fixture.root).is_err());
    fs::write(fixture.root.join("bin/archive.sha256"), digest(&body)).unwrap();
    fs::write(fixture.root.join("bin/manifest.json"), b"invalid").unwrap();
    assert!(read_installed(&fixture.root).is_err());
}

#[test]
fn old_install_metadata_is_not_adopted() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("install.json"), b"obsolete").unwrap();
    fs::remove_file(fixture.root.join("bin/manifest.json")).unwrap();
    assert!(read_installed(&fixture.root).is_err());
}

#[test]
fn tampered_extracted_file_is_rejected_before_publication() {
    let fixture = Fixture::new();
    let body = package("2.0.0", b"expected executable", false);
    let archive = fixture.temp.path().join("new.zip");
    fs::write(&archive, &body).unwrap();
    let (manifest, _) = crate::package::validate_contents(&archive, TARGET, "2.0.0").unwrap();
    let staging = fixture.temp.path().join("stage");
    self_update::Extract::from_source(&archive)
        .extract_into(&staging)
        .unwrap();
    let bundle = staging.join(format!("hostlink-agent-{TARGET}"));
    fs::write(bundle.join(ARCHIVE_DIGEST), digest(&body)).unwrap();
    fs::write(
        bundle.join(if TARGET.contains("windows") {
            "hostlink-agent.exe"
        } else {
            "hostlink-agent"
        }),
        b"tampered",
    )
    .unwrap();
    assert!(validate_installed(&bundle, &manifest, TARGET).is_err());
    assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
}

#[test]
fn archive_manifest_and_symlink_gates_are_bounded() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("package.zip");
    for bytes in [
        package("wrong", b"new executable", false),
        package("2.0.0", b"new executable", true),
    ] {
        fs::write(&archive, bytes).unwrap();
        assert!(crate::package::validate_contents(&archive, TARGET, "2.0.0").is_err());
    }
    let file = fs::File::create(&archive).unwrap();
    file.set_len(crate::package::MAX_ARCHIVE_BYTES + 1).unwrap();
    assert!(crate::package::validate_contents(&archive, TARGET, "2.0.0").is_err());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn locks_alias_and_installed_integrity_fail_before_network() {
    let fixture = Fixture::new();
    let url = format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip");
    let pin = digest(b"not downloaded");
    let root = ::private_fs::PrivateDir::open(&fixture.root).unwrap();
    for name in ["jobs/runner.lock", "update.lock"] {
        use crate::private_fs::PrivateFileExt;
        let lock = root
            .open_file_with(
                name,
                ::private_fs::OpenOptions {
                    access: ::private_fs::FileAccess::ReadWrite,
                    creation: ::private_fs::FileCreation::OpenOrCreate,
                    ..::private_fs::OpenOptions::default()
                },
            )
            .unwrap()
            .try_clone_std()
            .unwrap();
        lock.try_lock().unwrap();
        assert_eq!(
            update(&fixture.root, &url, &pin, TARGET, "2.0.0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
    assert!(update(&alias, &url, &pin, TARGET, "2.0.0").is_err());
    fs::write(fixture.root.join("bin/hostlink-agent"), b"tampered").unwrap();
    assert!(update(&fixture.root, &url, &pin, TARGET, "2.0.0").is_err());
}
