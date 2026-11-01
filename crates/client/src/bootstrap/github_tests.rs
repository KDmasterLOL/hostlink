use super::*;
use serde_json::{Value, json};
#[cfg(unix)]
use std::fs;

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
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("github-token");
    let missing = read_token_file(&path).unwrap_err().to_string();
    assert!(missing.contains("0600") && missing.contains("0700"));
    assert!(missing.contains("0400 must be reprovisioned"));
    fs::write(&path, b"synthetic_fixture\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_token_file(&path).unwrap().expose_secret(),
        "synthetic_fixture"
    );
    let link = root.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(read_token_file(&link).is_err());
    fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(read_token_file(&path).is_err());
    fs::remove_file(root.path().join("hardlink")).unwrap();
    for mode in [0o400, 0o640] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let error = read_token_file(&path).unwrap_err().to_string();
        assert_eq!(error, missing);
        assert!(!error.contains("synthetic_fixture"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    for valid in [
        b"synthetic_fixture\r\n".to_vec(),
        vec![b'a'; MAX_TOKEN_BYTES],
    ] {
        fs::write(&path, &valid).unwrap();
        assert_eq!(
            read_token_file(&path).unwrap().expose_secret(),
            std::str::from_utf8(&valid)
                .unwrap()
                .trim_end_matches(['\r', '\n'])
        );
    }
    for invalid in [
        vec![],
        b"\r\n".to_vec(),
        vec![b'a'; MAX_TOKEN_BYTES + 1],
        [vec![b'a'; MAX_TOKEN_BYTES], b"\n".to_vec()].concat(),
        b"bad\nheader".to_vec(),
        b" space".to_vec(),
        b"synthetic_fixture ".to_vec(),
        b"synthetic_fixture\0".to_vec(),
        vec![0xff],
    ] {
        fs::write(&path, invalid).unwrap();
        assert_eq!(read_token_file(&path).unwrap_err().to_string(), missing);
    }
}

#[cfg(unix)]
#[test]
fn credential_rejects_public_parent_without_changing_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("github-token");
    fs::write(&path, b"synthetic_fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_token_file(&path).is_err());
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn credential_rejects_symlinked_parent_and_ancestor() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let credentials = root.path().join("credentials");
    fs::create_dir(&credentials).unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
    let path = credentials.join("github-token");
    fs::write(&path, b"synthetic_fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_token_file(&path).is_ok());
    let parent_link = root.path().join("parent-link");
    symlink(&credentials, &parent_link).unwrap();
    assert!(read_token_file(&parent_link.join("github-token")).is_err());
    let ancestor_link = root.path().join("ancestor-link");
    symlink(root.path(), &ancestor_link).unwrap();
    assert!(read_token_file(&ancestor_link.join("credentials/github-token")).is_err());
}
