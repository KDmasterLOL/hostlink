use super::*;
use self_update::ReleaseSource;
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
fn source_and_public_https_pins_are_exact() {
    let url = format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip");
    let artifact = Artifact::new(
        &url,
        digest(b"independent artifact"),
        TARGET.into(),
        "2.0.0".into(),
    )
    .unwrap();
    assert_eq!(artifact.get_releases().unwrap().len(), 1);
    assert!(artifact.get_release_version("2.0.1").is_err());
    assert_eq!(
        artifact.get_release_version("2.0.0").unwrap().assets()[0].download_url(),
        url
    );
    for bad in [
        url.replace("https:", "http:"),
        url.replace("/v2.0.0/", "/v3.0.0/"),
        url.replace("artifacts.example", "user@artifacts.example"),
        format!("{url}#fragment"),
        url.replace("/v2.0.0/", "/%2e%2e/v2.0.0/"),
        url.replace("/v2.0.0/", "/v2.0.0/../v2.0.0/"),
    ] {
        assert!(
            Artifact::new(&bad, artifact.sha256.clone(), TARGET.into(), "2.0.0".into()).is_err()
        );
    }
    assert!(Artifact::new(&url, "bad digest".into(), TARGET.into(), "2.0.0".into()).is_err());
    assert!(
        Artifact::new(
            &url,
            artifact.sha256.clone(),
            "unsupported".into(),
            "2.0.0".into()
        )
        .is_err()
    );
}

#[test]
fn staged_bundle_metadata_and_installed_precedence() {
    let fixture = Fixture::new();
    let body = package("2.0.0", b"new executable", false);
    let archive = fixture.temp.path().join("new.zip");
    fs::write(&archive, &body).unwrap();
    let (manifest, bytes) = archive::validate_contents(&archive, TARGET, "2.0.0").unwrap();
    assert!(archive::validate_contents(&archive, TARGET, "wrong version").is_err());
    let staging = fixture.temp.path().join("stage");
    self_update::Extract::from_source(&archive)
        .extract_into(&staging)
        .unwrap();
    let bundle = staging.join(format!("hostlink-agent-{TARGET}"));
    let selected = Artifact::new(
        &format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip"),
        digest(&body),
        TARGET.into(),
        "2.0.0".into(),
    )
    .unwrap();
    publication::prepare_bundle(&bundle, &selected, &manifest, &bytes).unwrap();
    let metadata: manifest::InstallMetadata =
        serde_json::from_slice(&fs::read(bundle.join(INSTALL_METADATA)).unwrap()).unwrap();
    assert_eq!(metadata.format, 2);
    installed::validate_installed(&bundle, &metadata, TARGET).unwrap();
    // Reader fixtures exercise format precedence, not a substitute update implementation.
    fs::rename(fixture.root.join("bin"), fixture.root.join("old-bin")).unwrap();
    fs::rename(bundle, fixture.root.join("bin")).unwrap();
    assert_eq!(
        installed::read(&fixture.root).unwrap().installed_version,
        "2.0.0"
    );
    fs::write(fixture.root.join("bin/install.json"), b"invalid metadata").unwrap();
    assert!(
        installed::read(&fixture.root).is_err(),
        "corrupt new metadata must not fall back to stale root metadata"
    );
}

#[test]
fn extracted_file_digest_is_checked_before_bundle_publication() {
    let fixture = Fixture::new();
    let bytes = package("2.0.0", b"expected executable", false);
    let archive_path = fixture.temp.path().join("new.zip");
    fs::write(&archive_path, &bytes).unwrap();
    let (manifest, manifest_bytes) =
        archive::validate_contents(&archive_path, TARGET, "2.0.0").unwrap();
    let extracted = fixture.temp.path().join("extracted");
    self_update::Extract::from_source(&archive_path)
        .extract_into(&extracted)
        .unwrap();
    let bundle = extracted.join(format!("hostlink-agent-{TARGET}"));
    let executable = if TARGET.contains("windows") {
        "hostlink-agent.exe"
    } else {
        "hostlink-agent"
    };
    fs::write(bundle.join(executable), b"tampered after extraction").unwrap();
    let selected = Artifact::new(
        &format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip"),
        digest(&bytes),
        TARGET.into(),
        "2.0.0".into(),
    )
    .unwrap();
    assert!(publication::prepare_bundle(&bundle, &selected, &manifest, &manifest_bytes).is_err());
    assert_eq!(
        installed::read(&fixture.root).unwrap().installed_version,
        "1.0.0"
    );
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
        assert!(archive::validate_contents(&archive, TARGET, "2.0.0").is_err());
    }
    let file = fs::File::create(&archive).unwrap();
    file.set_len(MAX_ARCHIVE_BYTES + 1).unwrap();
    assert!(archive::validate_contents(&archive, TARGET, "2.0.0").is_err());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn locks_alias_and_installed_integrity_fail_before_network() {
    let fixture = Fixture::new();
    let request = AgentUpdateRequest {
        install_root: fixture.root.clone(),
        artifact: Artifact::new(
            &format!("https://artifacts.example/v2.0.0/hostlink-agent-{TARGET}.zip"),
            digest(b"not downloaded"),
            TARGET.into(),
            "2.0.0".into(),
        )
        .unwrap(),
    };
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
            apply(&request).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    let alias = fixture.temp.path().join("alias");
    std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
    let mut aliased = request.clone();
    aliased.install_root = alias;
    assert!(apply(&aliased).is_err());
    fs::write(fixture.root.join("bin/hostlink-agent"), b"tampered").unwrap();
    assert!(apply(&request).is_err());
}
