use super::*;
use serde_json::{Value, json};

fn metadata() -> Value {
    json!({"tag_name":"v1.2.3", "draft":false, "published_at":"2026-11-01", "assets":[
        {"name":"hostlink-agent-x86_64-unknown-linux-gnu", "url":format!("{RELEASES}/assets/1"), "state":"uploaded", "digest":format!("sha256:{}", "a".repeat(64))}
    ]})
}

#[test]
fn release_requires_exact_published_version_unique_asset_and_digest() {
    assert_eq!(
        release_url(None).unwrap().as_str(),
        format!("{RELEASES}/latest")
    );
    assert_eq!(
        release_url(Some("1.2.3")).unwrap().as_str(),
        format!("{RELEASES}/tags/v1.2.3")
    );
    assert!(release_url(Some("latest")).is_err());
    let parse = |value: &Value| parse_release(&serde_json::to_vec(value).unwrap(), Some("1.2.3"));
    let release = parse(&metadata()).unwrap();
    assert_eq!(
        select_asset(&release, &Target::LinuxX64.asset_name())
            .unwrap()
            .1,
        "a".repeat(64)
    );
    for target in [Target::Win7X86, Target::Win7X64, Target::Win11X64] {
        assert!(select_asset(&release, &target.asset_name()).is_err());
    }
    // Older script/ZIP assets must never substitute for the selected raw binary.
    for old in [
        "Install-HostLink-Agent.ps1",
        "hostlink-agent-x86_64-unknown-linux-gnu.zip",
    ] {
        let mut value = metadata();
        value["assets"][0]["name"] = json!(old);
        assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
    }
    for (key, bad) in [
        ("draft", json!(true)),
        ("published_at", Value::Null),
        ("tag_name", json!("v9.9.9")),
    ] {
        let mut value = metadata();
        value[key] = bad;
        assert!(parse(&value).is_err());
    }
    for (key, bad) in [
        ("digest", Value::Null),
        ("digest", json!("sha256:abc")),
        ("state", json!("new")),
    ] {
        let mut value = metadata();
        value["assets"][0][key] = bad;
        assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
    }
    let mut value = metadata();
    let duplicate = value["assets"][0].clone();
    value["assets"].as_array_mut().unwrap().push(duplicate);
    assert!(select_asset(&parse(&value).unwrap(), &Target::LinuxX64.asset_name()).is_err());
}

#[test]
fn authenticated_request_is_sensitive_and_fixed_to_repository_api() {
    let client = github_client().unwrap();
    let token = SecretString::from("synthetic_fixture");
    let request = authenticated_get(
        &client,
        release_url(None).unwrap(),
        &token,
        "application/octet-stream",
    )
    .unwrap()
    .build()
    .unwrap();
    assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
    assert!(
        authenticated_get(
            &client,
            Url::parse("https://elsewhere.invalid/").unwrap(),
            &token,
            "application/octet-stream"
        )
        .is_err()
    );
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::FOUND,
    ] {
        let error = require_ok(status).unwrap_err().to_string();
        assert!(error.contains(&status.as_u16().to_string()));
        assert!(!error.contains(token.expose_secret()));
    }
}

#[cfg(unix)]
#[test]
fn credential_requires_private_regular_bounded_single_link_file() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("github-token");
    assert!(read_token_file(&path).is_err());
    fs::write(&path, b"synthetic_fixture\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_token_file(&path).is_ok());
    let link = root.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(read_token_file(&link).is_err());
    fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(read_token_file(&path).is_err());
    fs::remove_file(root.path().join("hardlink")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_token_file(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    for invalid in [
        vec![],
        vec![b'a'; MAX_TOKEN_BYTES + 1],
        b"bad\nheader".to_vec(),
        b" space".to_vec(),
        vec![0xff],
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(read_token_file(&path).is_err());
    }
}
