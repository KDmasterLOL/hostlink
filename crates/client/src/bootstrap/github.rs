//! Fixed private GitHub Releases owner: credentials, metadata, names and digests.
//! The API digest authenticates selected bytes, not an independent publisher signature.
//! Security contract kept together; tests are inline while sibling tests.rs has another owner.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use reqwest::{Client, RequestBuilder, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use super::validate::{
    ArtifactSelection, BootstrapError, INSTALLER_TIMEOUT, Target, semver, sha256,
    validate_github_asset_url,
};
use super::verify::read_bounded;

const RELEASES: &str = "https://api.github.com/repos/KDmasterLOL/hostlink/releases";
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 4096;

fn source(message: &str) -> BootstrapError {
    BootstrapError::Source(message.into())
}

fn credential_path() -> Result<PathBuf, BootstrapError> {
    #[cfg(windows)]
    let path = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join("HostLink/credentials/github-token"));
    #[cfg(not(windows))]
    let path = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join("hostlink/credentials/github-token"))
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(".config/hostlink/credentials/github-token"))
        });
    path.ok_or_else(|| source("GitHub credential location unavailable (absolute HOME/XDG_CONFIG_HOME or APPDATA required)"))
}

pub(super) fn read_token() -> Result<SecretString, BootstrapError> {
    read_token_file(&credential_path()?)
}

fn read_token_file(path: &Path) -> Result<SecretString, BootstrapError> {
    let invalid = || {
        source(
            "GitHub credential missing, unsafe or invalid; provision an owner-only credentials/github-token file with a fine-grained PAT (Contents:Read) on this controller",
        )
    };
    let before = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > MAX_TOKEN_BYTES as u64
    {
        return Err(invalid());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES as u64 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    crate::connect::validate_private_file(&file).map_err(|_| invalid())?;
    #[cfg(not(any(unix, windows)))]
    return Err(invalid());
    let mut text = String::new();
    file.take((MAX_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|_| invalid())?;
    let text = SecretString::from(text);
    let value = text.expose_secret().trim_end_matches(['\r', '\n']);
    if text.expose_secret().len() > MAX_TOKEN_BYTES
        || value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid());
    }
    Ok(SecretString::from(value))
}

pub(super) fn github_client() -> Result<Client, BootstrapError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(INSTALLER_TIMEOUT)
        .user_agent("HostLink-release-preflight")
        .build()
        .map_err(|_| source("could not create GitHub HTTPS client"))
}

pub(super) fn authenticated_get(
    client: &Client,
    url: Url,
    token: &SecretString,
    accept: &str,
) -> Result<RequestBuilder, BootstrapError> {
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url
            .path()
            .starts_with("/repos/KDmasterLOL/hostlink/releases/")
    {
        return Err(BootstrapError::Invalid(
            "GitHub credentials may only be sent to the fixed repository API",
        ));
    }
    Ok(client
        .get(url)
        .bearer_auth(token.expose_secret())
        .header(reqwest::header::ACCEPT, accept)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .header("X-GitHub-Api-Version", "2022-11-28"))
}

pub(super) fn require_ok(status: StatusCode) -> Result<(), BootstrapError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED => Err(source(
            "GitHub authentication failed (HTTP 401); check the controller credential",
        )),
        StatusCode::FORBIDDEN => Err(source(
            "GitHub access denied or rate limited (HTTP 403); private KDmasterLOL/hostlink requires fine-grained Contents:Read access",
        )),
        StatusCode::NOT_FOUND => Err(source(
            "GitHub release/asset not found (HTTP 404); private KDmasterLOL/hostlink may be inaccessible or have no published matching release",
        )),
        _ => Err(source(&format!(
            "GitHub source returned unexpected HTTP {}",
            status.as_u16()
        ))),
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    published_at: Option<String>,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    url: String,
    digest: Option<String>,
    state: String,
}

fn release_url(version: Option<&str>) -> Result<Url, BootstrapError> {
    let suffix = match version {
        Some(version) if semver(version) => format!("tags/v{version}"),
        Some(_) => {
            return Err(BootstrapError::Invalid(
                "--version must be an exact semantic version; release tags use vX.Y.Z",
            ));
        }
        None => "latest".into(),
    };
    Url::parse(&format!("{RELEASES}/{suffix}")).map_err(|_| source("invalid GitHub release URL"))
}

fn parse_release(
    bytes: &[u8],
    requested: Option<&str>,
) -> Result<(Release, String), BootstrapError> {
    let release: Release =
        serde_json::from_slice(bytes).map_err(|_| source("GitHub release metadata is invalid"))?;
    let version = release
        .tag_name
        .strip_prefix('v')
        .filter(|version| semver(version))
        .ok_or_else(|| source("GitHub release must have an exact vX.Y.Z semantic tag"))?
        .to_owned();
    if release.draft
        || release.published_at.as_deref().is_none_or(str::is_empty)
        || requested.is_some_and(|requested| requested != version)
    {
        return Err(source(
            "GitHub release is unpublished, draft, or does not match the requested exact version",
        ));
    }
    Ok((release, version))
}

fn select_asset(release: &Release, name: &str) -> Result<(Url, String), BootstrapError> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| source(&format!("GitHub release lacks required asset {name}")))?;
    if matches.next().is_some() || asset.state != "uploaded" {
        return Err(source(
            "GitHub release asset name is ambiguous or not uploaded",
        ));
    }
    let digest = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| sha256(&digest.to_ascii_lowercase()))
        .ok_or_else(|| {
            source("every selected GitHub asset requires a published sha256:<64 hex> digest")
        })?;
    let url = super::parse_artifact_url(&asset.url)?;
    validate_github_asset_url(&url)?;
    Ok((url, digest.to_ascii_lowercase()))
}

/// Resolve only the fixed private repository's latest release or exact `vX.Y.Z` tag.
/// Credentials stay local; caller must verify the installer before POST /v2/invites.
/// GitHub SHA-256 metadata is authenticated, not an independent publisher signature.
pub async fn resolve_github_selection(
    version: Option<&str>,
    target: Target,
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
) -> Result<ArtifactSelection, BootstrapError> {
    let url = release_url(version)?;
    let token = read_token()?;
    let client = github_client()?;
    let response = authenticated_get(&client, url, &token, "application/vnd.github+json")?
        .send()
        .await
        .map_err(|_| source("GitHub release request failed or timed out"))?;
    require_ok(response.status())?;
    let bytes = read_bounded(response, MAX_METADATA_BYTES).await?;
    let (release, version) = parse_release(&bytes, version)?;
    selection_from_release(
        &release,
        version,
        target,
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
    )
}

fn selection_from_release(
    release: &Release,
    version: String,
    target: Target,
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
) -> Result<ArtifactSelection, BootstrapError> {
    let installer = if target.windows() {
        "Install-HostLink-Agent.ps1"
    } else {
        "install-hostlink-agent.sh"
    };
    let sidecar = format!(
        "hostlink-agent-{}{}",
        target.as_str(),
        if target.windows() { ".exe" } else { "" }
    );
    let archive = format!("hostlink-agent-{}.zip", target.as_str());
    let (installer_url, installer_sha256) = select_asset(release, installer)?;
    let (agent_url, agent_sha256) = select_asset(release, &sidecar)?;
    let (archive_url, archive_sha256) = select_asset(release, &archive)?;
    let selection = ArtifactSelection {
        installer_url,
        installer_sha256,
        agent_url,
        agent_sha256,
        archive_url,
        archive_sha256,
        version,
        target,
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
    };
    selection.validate()?;
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture(target: Target) -> Value {
        let installer = if target.windows() {
            "Install-HostLink-Agent.ps1"
        } else {
            "install-hostlink-agent.sh"
        };
        let names = [
            installer.to_owned(),
            format!(
                "hostlink-agent-{}{}",
                target.as_str(),
                if target.windows() { ".exe" } else { "" }
            ),
            format!("hostlink-agent-{}.zip", target.as_str()),
        ];
        json!({"tag_name":"v1.2.3", "draft":false, "published_at":"2026-11-01T00:00:00Z", "assets": names.iter().enumerate().map(|(index, name)| json!({"name":name, "url":format!("{RELEASES}/assets/{}",index+1),"state":"uploaded","digest":format!("sha256:{}", "a".repeat(64))})).collect::<Vec<_>>()})
    }

    fn select(value: &Value, target: Target) -> Result<ArtifactSelection, BootstrapError> {
        let (release, version) = parse_release(&serde_json::to_vec(value).unwrap(), Some("1.2.3"))?;
        selection_from_release(
            &release,
            version,
            target,
            "fixture".into(),
            "hostlink".into(),
            "https://hub.example".into(),
            None,
        )
    }

    #[test]
    fn latest_and_exact_tag_are_fixed_endpoints() {
        assert_eq!(
            release_url(None).unwrap().as_str(),
            format!("{RELEASES}/latest")
        );
        assert_eq!(
            release_url(Some("1.2.3")).unwrap().as_str(),
            format!("{RELEASES}/tags/v1.2.3")
        );
        for invalid in ["latest", "v1.2.3", "1.2", "1.2.3/path", "01.2.3"] {
            assert!(release_url(Some(invalid)).is_err());
        }
    }

    #[test]
    fn all_four_targets_require_exact_flat_asset_names_and_digests() {
        for target in [
            Target::LinuxX64,
            Target::Win7X86,
            Target::Win7X64,
            Target::Win11X64,
        ] {
            let mut value = fixture(target);
            let selection = select(&value, target).unwrap();
            assert_eq!(selection.version, "1.2.3");
            assert_eq!(selection.agent_url.as_str(), format!("{RELEASES}/assets/2"));
            for index in 0..3 {
                let original = value["assets"][index].clone();
                value["assets"][index]["digest"] = Value::Null;
                assert!(select(&value, target).is_err());
                value["assets"][index] = original.clone();
                value["assets"][index]["name"] =
                    json!(format!("nested/{}", original["name"].as_str().unwrap()));
                assert!(select(&value, target).is_err());
                value["assets"][index] = original;
            }
        }
    }

    #[test]
    fn missing_duplicate_and_aliased_assets_fail_closed() {
        let target = Target::LinuxX64;
        for index in 0..3 {
            let mut value = fixture(target);
            let duplicate = value["assets"][index].clone();
            value["assets"].as_array_mut().unwrap().push(duplicate);
            assert!(select(&value, target).is_err());
            let mut value = fixture(target);
            value["assets"].as_array_mut().unwrap().remove(index);
            assert!(select(&value, target).is_err());
        }
        let mut value = fixture(target);
        value["assets"][1]["url"] = value["assets"][0]["url"].clone();
        assert!(select(&value, target).is_err());
        value = fixture(target);
        value["assets"][1]["state"] = json!("new");
        assert!(select(&value, target).is_err());
    }

    #[test]
    fn unpublished_invalid_or_wrong_version_never_selects_assets() {
        for (key, bad) in [
            ("draft", json!(true)),
            ("published_at", Value::Null),
            ("published_at", json!("")),
            ("tag_name", json!("v9.9.9")),
            ("tag_name", json!("1.2.3")),
            ("tag_name", json!("vlatest")),
        ] {
            let mut value = fixture(Target::LinuxX64);
            value[key] = bad;
            assert!(select(&value, Target::LinuxX64).is_err());
        }
        assert!(parse_release(b"{}", None).is_err());
        assert!(parse_release(b"[]", None).is_err());
    }

    #[test]
    fn every_asset_requires_fixed_private_api_origin_and_numeric_id() {
        for invalid in [
            "https://example.com/asset",
            "https://api.github.com/repos/other/hostlink/releases/assets/1",
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/0",
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/abc",
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1?x=1",
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1#x",
            "https://user@api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
            "https://api.github.com:444/repos/KDmasterLOL/hostlink/releases/assets/1",
        ] {
            for index in 0..3 {
                let mut value = fixture(Target::LinuxX64);
                value["assets"][index]["url"] = json!(invalid);
                assert!(select(&value, Target::LinuxX64).is_err());
            }
        }
        for invalid in [
            "md5:1234".to_owned(),
            format!("sha256:{}", "g".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
        ] {
            let mut value = fixture(Target::LinuxX64);
            value["assets"][0]["digest"] = json!(invalid);
            assert!(select(&value, Target::LinuxX64).is_err());
        }
    }

    #[test]
    fn authenticated_request_is_restricted_and_sensitive_without_network() {
        let client = github_client().unwrap();
        let token = SecretString::from("nonsecret_fixture");
        let request = authenticated_get(
            &client,
            release_url(None).unwrap(),
            &token,
            "application/octet-stream",
        )
        .unwrap()
        .build()
        .unwrap();
        assert!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap()
                .is_sensitive()
        );
        assert_eq!(
            request.headers()[reqwest::header::ACCEPT],
            "application/octet-stream"
        );
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
        fs::write(&path, b"nonsecret_fixture\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_token_file(&path).is_ok());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_token_file(&link).is_err());
        let hardlink = root.path().join("hardlink");
        fs::hard_link(&path, &hardlink).unwrap();
        assert!(read_token_file(&path).is_err());
        fs::remove_file(hardlink).unwrap();
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
        assert!(read_token_file(root.path()).is_err());
    }
}
