use super::*;

fn asset(name: &str) -> ReleaseAsset {
    ReleaseAsset::new(
        name,
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
    )
    .with_digest(format!("sha256:{}", "ab".repeat(32)))
}

#[test]
fn only_four_exact_raw_asset_names_are_supported() {
    for (target, name) in [
        (
            "x86_64-unknown-linux-gnu",
            "hostlink-agent-x86_64-unknown-linux-gnu",
        ),
        (
            "x86_64-pc-windows-msvc",
            "hostlink-agent-x86_64-pc-windows-msvc.exe",
        ),
        (
            "x86_64-win7-windows-msvc",
            "hostlink-agent-x86_64-win7-windows-msvc.exe",
        ),
        (
            "i686-win7-windows-msvc",
            "hostlink-agent-i686-win7-windows-msvc.exe",
        ),
    ] {
        assert_eq!(asset_name(target).unwrap(), name);
        let (selected, digest) = selected_asset(
            &[
                asset(&format!("{name}.zip")),
                asset(&format!("prefix-{name}")),
                asset(name),
            ],
            target,
        )
        .unwrap();
        assert_eq!(selected.name(), name);
        assert_eq!(digest, "ab".repeat(32));
        assert!(selected_asset(&[asset(&format!("{name}.zip"))], target).is_err());
        assert!(selected_asset(&[asset(name), asset(name)], target).is_err());
    }
    for target in [
        "i686-pc-windows-msvc",
        "aarch64-unknown-linux-gnu",
        "../target",
        "",
    ] {
        assert!(asset_name(target).is_err());
    }
}

#[test]
fn published_sha256_is_mandatory_and_must_be_exactly_32_bytes() {
    let target = "x86_64-unknown-linux-gnu";
    let name = asset_name(target).unwrap();
    assert!(
        selected_asset(
            &[ReleaseAsset::new(
                &name,
                "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1"
            )],
            target
        )
        .is_err()
    );
    for digest in ["sha256:", "sha512:aa", "sha256:abcd", "sha256:not-hex"] {
        assert!(selected_asset(&[asset(&name).with_digest(digest)], target).is_err());
    }
}

#[test]
fn public_download_is_bound_to_release_not_asset_api_url() {
    let target = "x86_64-unknown-linux-gnu";
    let name = asset_name(target).unwrap();
    let ignored_url = ReleaseAsset::new(&name, "https://example.invalid/untrusted")
        .with_digest(format!("sha256:{}", "ab".repeat(32)));
    let selected = selected_asset(&[ignored_url], target).unwrap().0;
    let version = Version::parse("1.2.3").unwrap();
    let download =
        public_download_asset(std::slice::from_ref(&selected), &selected, &version).unwrap();
    assert_eq!(
        download.download_url(),
        format!("https://github.com/KDmasterLOL/hostlink/releases/download/v1.2.3/{name}")
    );
    assert_eq!(download.digest(), selected.digest());
    assert!(
        public_download_asset(&[selected.clone(), selected.clone()], &selected, &version).is_none()
    );
    assert!(
        public_download_asset(
            &[asset(&name).with_digest(format!("sha256:{}", "cd".repeat(32)))],
            &selected,
            &version
        )
        .is_none()
    );
    let changed_api_url = ReleaseAsset::new(&name, "https://another.invalid/ignored")
        .with_digest(selected.digest().unwrap());
    assert_eq!(
        public_download_asset(&[changed_api_url], &selected, &version)
            .unwrap()
            .download_url(),
        format!("https://github.com/KDmasterLOL/hostlink/releases/download/v1.2.3/{name}")
    );
}

#[test]
fn offline_locks_are_exclusive_without_inspecting_apalis() {
    let temp = tempfile::tempdir().unwrap();
    let dir = PrivateDir::ensure(temp.path().join("Agent")).unwrap();
    let root = temp.path().join("Agent");
    dir.create_dir("jobs").unwrap();
    for (parent, name) in [
        (root.clone(), "update.lock"),
        (root.join("jobs"), "runner.lock"),
    ] {
        let first = lock(&parent, name).unwrap();
        assert_eq!(
            lock(&parent, name).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        drop(lock(&parent, name).unwrap());
    }
    assert!(!root.join("jobs/jobs.db").exists());
}

#[test]
fn release_tag_url_must_match_the_exact_canonical_version() {
    let version = Version::parse("1.2.3").unwrap();
    for (url, valid) in [
        (
            "https://github.com/KDmasterLOL/hostlink/releases/tag/v1.2.3",
            true,
        ),
        (
            "https://github.com/KDmasterLOL/hostlink/releases/tag/1.2.3",
            false,
        ),
        (
            "https://github.com/KDmasterLOL/hostlink/releases/tag/vv1.2.3",
            false,
        ),
        (
            "https://github.com/KDmasterLOL/hostlink/releases/tag/v1.2.4",
            false,
        ),
        (
            "https://github.com.evil.test/KDmasterLOL/hostlink/releases/tag/v1.2.3",
            false,
        ),
    ] {
        let release = Release::builder()
            .version("1.2.3")
            .release_notes_url(url)
            .build()
            .unwrap();
        assert_eq!(
            validate_release_tag(&release, &version).is_ok(),
            valid,
            "{url}"
        );
    }
    let release = Release::builder().version("1.2.3").build().unwrap();
    assert!(validate_release_tag(&release, &version).is_err());
}
