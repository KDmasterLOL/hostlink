//! Fixed private GitHub Releases owner: credentials, metadata, names and digests.
//! The API digest authenticates selected bytes, not an independent publisher signature.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use private_fs::PrivateDir;
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use super::validate::{
    ArtifactSelection, BootstrapError, METADATA_TIMEOUT, Target, semver, sha256, validate_https_url,
};

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
            "GitHub credential missing, unsafe or invalid; explicitly provision credentials/github-token with a fine-grained PAT (Contents:Read) on this controller; managed credentials require Unix file mode 0600 (0400 must be reprovisioned) and parent directory mode 0700, or Windows owner-only DACLs",
        )
    };
    let parent = path.parent().ok_or_else(invalid)?;
    let name = path.file_name().ok_or_else(invalid)?;
    let directory = PrivateDir::open(parent).map_err(|_| invalid())?;
    let file = directory.open_file(name).map_err(|_| invalid())?;
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
        .timeout(METADATA_TIMEOUT)
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
    validate_https_url(&url)?;
    if url.host_str() != Some("api.github.com")
        || url.port().is_some()
        || url.query().is_some()
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

fn parse_release(bytes: &[u8], requested: Option<&str>) -> Result<Release, BootstrapError> {
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
    Ok(release)
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
    let url = Url::parse(&asset.url).map_err(|_| source("invalid GitHub asset URL"))?;
    super::validate::validate_github_asset_url(&url)?;
    Ok((url, digest.to_ascii_lowercase()))
}

/// Resolve only the fixed private repository's latest release or exact `vX.Y.Z` tag.
/// Credentials stay local; the target must verify the binary before enrollment.
/// GitHub SHA-256 metadata is authenticated, not an independent publisher signature.
pub async fn resolve_github_selection(
    version: Option<&str>,
    target: Target,
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
    gateway_index: Option<usize>,
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
    let release = parse_release(&bytes, version)?;
    let (agent_url, agent_sha256) = select_asset(&release, &target.asset_name())?;
    let selection = ArtifactSelection {
        agent_url,
        agent_sha256,
        target,
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
        gateway_index,
    };
    selection.validate()?;
    Ok(selection)
}

pub(super) async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BootstrapError> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(BootstrapError::Source(
            "GitHub source used an unexpected content encoding".into(),
        ));
    }
    if let Some(length) = response.headers().get(reqwest::header::CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| BootstrapError::Source("GitHub source length is invalid".into()))?;
        if length > limit as u64 {
            return Err(BootstrapError::Source(
                "GitHub source exceeds the byte limit".into(),
            ));
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BootstrapError::Source("GitHub source download failed".into()))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(BootstrapError::Source(
                "GitHub source exceeds the byte limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "github_tests.rs"]
mod tests;
