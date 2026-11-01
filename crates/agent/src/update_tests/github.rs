//! Pure release-metadata tests. The private GitHub repository has no published
//! releases yet; these cases do not invent or publish one.

use super::*;

fn release(version: &str, target: &str, digest: Option<&str>, url: &str) -> Release {
    let mut asset = ReleaseAsset::new(format!("hostlink-agent-{target}.zip"), url);
    if let Some(digest) = digest {
        asset = asset.with_digest(digest);
    }
    Release::builder()
        .version(version)
        .asset(asset)
        .build()
        .unwrap()
}

fn asset_url(id: u64) -> String {
    format!("https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/{id}")
}

fn pin() -> String {
    format!("sha256:{}", "a5".repeat(32))
}

#[test]
fn latest_uses_greatest_stable_compatible_version_not_listing_order() {
    let pin = pin();
    let releases = [
        release("1.10.0", TARGET, Some(&pin), &asset_url(10)),
        release("9.0.0-beta.1", TARGET, Some(&pin), &asset_url(9)),
        release("2.1.0", "unsupported-target", Some(&pin), &asset_url(21)),
        release("1.2.0", TARGET, Some(&pin), &asset_url(12)),
    ];
    let (url, digest, version) = select_github_asset(&releases, TARGET, None).unwrap();
    assert_eq!(version, semver::Version::parse("1.10.0").unwrap());
    assert_eq!(digest, [0xa5; 32]);
    assert_eq!(url.as_str(), asset_url(10));
}

#[test]
fn exact_older_or_prerelease_can_be_selected_explicitly() {
    let pin = pin();
    let releases = [
        release("0.9.0", TARGET, Some(&pin), &asset_url(9)),
        release("2.0.0-beta.2", TARGET, Some(&pin), &asset_url(20)),
        release("2.1.0", TARGET, Some(&pin), &asset_url(21)),
    ];
    for (requested, id) in [("0.9.0", 9), ("2.0.0-beta.2", 20)] {
        let requested = semver::Version::parse(requested).unwrap();
        let (url, _, version) = select_github_asset(&releases, TARGET, Some(&requested)).unwrap();
        assert_eq!(version, requested);
        assert_eq!(url.as_str(), asset_url(id));
    }
}

#[test]
fn missing_releases_and_requested_versions_fail_instead_of_claiming_current() {
    assert!(select_github_asset(&[], TARGET, None).is_err());
    let releases = [release("1.0.0", TARGET, Some(&pin()), &asset_url(1))];
    let requested = semver::Version::parse("5.0.0").unwrap();
    assert!(select_github_asset(&releases, TARGET, Some(&requested)).is_err());
}

#[test]
fn rejects_missing_wrong_or_malformed_release_digests() {
    for invalid in [
        None,
        Some("sha512:deadbeef"),
        Some("sha256:abcd"),
        Some("sha256:zzzz"),
    ] {
        let releases = [release("1.2.0", TARGET, invalid, &asset_url(12))];
        assert!(
            select_github_asset(&releases, TARGET, None).is_err(),
            "accepted digest: {invalid:?}"
        );
    }
}

#[test]
fn rejects_wrong_repository_or_unsafe_asset_urls() {
    for url in [
        "https://attacker.example/payload.zip",
        "http://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com/repos/other/hostlink/releases/assets/1",
        "https://user:secret@api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1?token=secret",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1#fragment",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/abc",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/0",
    ] {
        let releases = [release("1.0.0", TARGET, Some(&pin()), url)];
        assert!(
            select_github_asset(&releases, TARGET, None).is_err(),
            "accepted unsafe asset URL: {url}"
        );
    }
}

#[test]
fn rejects_duplicate_version_and_target_assets() {
    let first = release("1.1.0", TARGET, Some(&pin()), &asset_url(1));
    let second = release("1.1.0", TARGET, Some(&pin()), &asset_url(2));
    assert!(select_github_asset(&[first, second], TARGET, None).is_err());

    let ambiguous = Release::builder()
        .version("1.1.0")
        .asset(
            ReleaseAsset::new(format!("hostlink-agent-{TARGET}.zip"), asset_url(1))
                .with_digest(pin()),
        )
        .asset(
            ReleaseAsset::new(format!("hostlink-agent-{TARGET}.zip"), asset_url(2))
                .with_digest(pin()),
        )
        .build()
        .unwrap();
    assert!(select_github_asset(&[ambiguous], TARGET, None).is_err());
}

#[test]
fn publication_guard_rejects_drafts_unstable_latest_invalid_tags_and_large_bodies() {
    let metadata = |tag: &str, draft: bool, prerelease: bool| {
        serde_json::to_vec(&serde_json::json!({
            "tag_name": tag, "draft": draft, "prerelease": prerelease
        }))
        .unwrap()
    };
    for tag in ["1.2.3", "v1.2.3"] {
        assert!(validate_github_metadata(&metadata(tag, false, false), true).is_ok());
        assert!(validate_github_metadata(&metadata(tag, true, false), false).is_err());
        assert!(validate_github_metadata(&metadata(tag, false, true), true).is_err());
    }
    for tag in ["vv1.2.3", "release-1.2.3", "1.2", "", "1.2.3\n"] {
        assert!(validate_github_metadata(&metadata(tag, false, false), false).is_err());
    }
    for prerelease in [false, true] {
        let body = metadata("v2.0.0-beta.1", false, prerelease);
        assert!(validate_github_metadata(&body, true).is_err());
        assert!(validate_github_metadata(&body, false).is_ok());
    }
    for body in [
        b"{}".as_slice(),
        b"[]",
        b"null",
        b"not JSON",
        br#"{"draft":false,"prerelease":false}"#,
    ] {
        assert!(validate_github_metadata(body, true).is_err());
    }
    let mut oversized = metadata("v1.2.3", false, false);
    oversized.resize(MAX_METADATA_BYTES as usize + 1, b' ');
    assert!(validate_github_metadata(&oversized, false).is_err());
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn latest_selection_cannot_downgrade_or_republish_same_version() {
    let fixture = Fixture::new();
    let old = read_installed(&fixture.root).unwrap().1;
    for version in ["0.9.0", "1.0.0", "1.0.0-beta.1"] {
        assert!(
            !apply_selected(
                &fixture.root,
                &Url::parse("https://127.0.0.1:1/not-requested.zip").unwrap(),
                [0xa5; 32],
                TARGET,
                &Version::parse(version).unwrap(),
                Update::configure(),
                true
            )
            .unwrap()
        );
        assert_eq!(read_installed(&fixture.root).unwrap().1, old);
    }
}
