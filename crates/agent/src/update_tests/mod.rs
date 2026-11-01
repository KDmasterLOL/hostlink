use super::*;
use std::{fs, io};

mod fixture;
mod github;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod http;
use fixture::{Fixture, digest, package};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(windows, target_arch = "x86_64"))]
const TARGET: &str = "x86_64-win7-windows-msvc";
#[cfg(all(windows, target_arch = "x86"))]
const TARGET: &str = "i686-win7-windows-msvc";

// The CLI owns decoding of text input. Preserve the previous invalid-input
// coverage while exercising the public updater with actual parsed types.
fn update(
    root: &std::path::Path,
    url: &str,
    sha256: &str,
    target: &str,
    version: &str,
) -> io::Result<bool> {
    let url = reqwest::Url::parse(url).map_err(|_| invalid("invalid artifact URL"))?;
    let sha256 = hex::decode(sha256).map_err(|_| invalid("invalid SHA-256"))?;
    let sha256: [u8; 32] = sha256
        .try_into()
        .map_err(|_| invalid("SHA-256 must be exactly 32 bytes"))?;
    let version =
        semver::Version::parse(version).map_err(|_| invalid("exact semantic version required"))?;
    super::update(root, &url, sha256, target, &version)
}

#[test]
fn parsed_updater_contract_reaches_the_lock_without_revalidating_text() {
    let fixture = Fixture::new();
    let _lock = held_lock(&fixture, "update.lock");
    let url =
        reqwest::Url::parse("https://artifacts.example/pinned-package?token=not-a-secret").unwrap();
    let version = semver::Version::parse("2.0.0").unwrap();
    let sha256 = [0xa5_u8; 32];
    assert_eq!(
        super::update(&fixture.root, &url, sha256, TARGET, &version)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unknown_development_binary_does_not_guess_an_installed_root() {
    assert!(default_update_root().is_err());
}

#[test]
fn https_artifact_paths_and_queries_reach_the_lock_gate() {
    let fixture = Fixture::new();
    let _lock = held_lock(&fixture, "update.lock");
    let pin = digest(b"independent artifact");
    // Hex parsing accepts either case; the canonical persisted archive SHA is
    // encoded in lowercase by the actual updater.
    assert_eq!(
        update(
            &fixture.root,
            "https://artifacts.example/bytes",
            &pin.to_uppercase(),
            TARGET,
            "2.0.0"
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::WouldBlock
    );
    for url in [
        format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip"),
        "https://artifacts.example/objects/download".to_owned(),
        "https://artifacts.example/a%20b/build%2Fagent.bin?signature=a%2Bb&key=user@example.com"
            .to_owned(),
        "https://ARTIFACTS.example:443/old/../objects/./bundle?version=unrelated".to_owned(),
        "https://artifacts.example/%2e%2e/objects/bundle".to_owned(),
    ] {
        // A generic error could be URL rejection. Contention proves that URL,
        // version, target and digest validation succeeded without network I/O.
        assert_eq!(
            update(&fixture.root, &url, &pin, TARGET, "2.0.0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock,
            "accepted URL must reach the held lock: {url}"
        );
    }
}

#[test]
fn artifact_trust_boundary_rejects_invalid_inputs_before_the_lock_gate() {
    let fixture = Fixture::new();
    let _lock = held_lock(&fixture, "update.lock");
    let url = format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip");
    let pin = digest(b"independent artifact");
    for bad in [
        url.replace("https:", "http:"),
        url.replace("https:", "ftp:"),
        url.replace("https:", "file:"),
        url.replace("artifacts.example", "user@artifacts.example"),
        url.replace("artifacts.example", "user:secret@artifacts.example"),
        url.replace("artifacts.example", ":secret@artifacts.example"),
        url.replace("artifacts.example", "%75ser@artifacts.example"),
        format!("{url}#fragment"),
        format!("{url}#"),
        url.replace("artifacts.example", "artifacts.example:0"),
        url.replace("artifacts.example", "artifacts.example:65536"),
        url.replace("artifacts.example", "artifacts.example:invalid"),
        "https://".to_owned(),
        "not a URL".to_owned(),
        "http://127.0.0.1:0/download".to_owned(),
        "http://127.0.0.1/download".to_owned(),
        "http://127.0.0.2:12345/download".to_owned(),
        "http://localhost:12345/download".to_owned(),
        "http://[::1]:12345/download".to_owned(),
    ] {
        assert_eq!(
            update(&fixture.root, &bad, &pin, TARGET, "2.0.0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput,
            "unsafe URL must fail before the held lock: {bad}"
        );
    }
    for bad in [
        "".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(64),
    ] {
        assert_eq!(
            update(&fixture.root, &url, &bad, TARGET, "2.0.0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let foreign_target = crate::package::supported_targets()
        .iter()
        .find(|target| !crate::package::target_matches_runtime(target))
        .unwrap();
    for bad in ["", "unsupported", *foreign_target] {
        assert_eq!(
            update(&fixture.root, &url, &pin, bad, "2.0.0")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    for bad in ["", "not-semver", "v2.0.0", "2.0"] {
        assert_eq!(
            update(&fixture.root, &url, &pin, TARGET, bad)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(read_installed(&fixture.root).unwrap().0.version, "1.0.0");
}

#[test]
fn selected_release_source_preserves_exact_version_and_asset() {
    let url = "https://artifacts.example/objects/a%20b?signature=a%2Bb";
    let release = Release::builder()
        .version("2.0.0")
        .asset(ReleaseAsset::new(
            format!("hostlink-agent-{TARGET}.zip"),
            url,
        ))
        .build()
        .unwrap();
    let selected = SelectedRelease(release);
    assert_eq!(selected.get_releases().unwrap().len(), 1);
    assert!(matches!(
        selected.get_release_version("2.0.1"),
        Err(self_update::Error::NoReleaseFound { .. })
    ));
    let exact = selected.get_release_version("2.0.0").unwrap();
    assert_eq!(exact.version(), "2.0.0");
    assert_eq!(
        exact.assets()[0].name(),
        format!("hostlink-agent-{TARGET}.zip")
    );
    assert_eq!(exact.assets()[0].download_url(), url);
}

fn held_lock(fixture: &Fixture, name: &str) -> fs::File {
    let lock = ::private_fs::PrivateDir::open(&fixture.root)
        .unwrap()
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
    lock
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
    assert_eq!(hex::encode(archive_digest), digest(&body));

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
    for name in ["jobs/runner.lock", "update.lock"] {
        let _lock = held_lock(&fixture, name);
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
