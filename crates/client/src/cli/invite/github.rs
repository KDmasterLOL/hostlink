//! Public release metadata and digest preflight for the fixed GitHub repository.
//! The API digest authenticates selected bytes, not an independent publisher signature.

use std::path::PathBuf;

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;

use super::validate::{
    ArtifactSelection, BootstrapError, METADATA_TIMEOUT, OsFamily, Target, semver, sha256,
};

const RELEASES: &str = "https://api.github.com/repos/KDmasterLOL/hostlink/releases";
const MAX_METADATA_BYTES: usize = 1024 * 1024;

fn source(message: &str) -> BootstrapError {
    BootstrapError::Source(message.into())
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

pub(super) fn require_ok(status: StatusCode) -> Result<(), BootstrapError> {
    if status == StatusCode::OK {
        Ok(())
    } else {
        Err(source(&format!(
            "GitHub public release metadata returned HTTP {}",
            status.as_u16()
        )))
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
    digest: Option<String>,
    state: String,
    size: u64,
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
    if matches.next().is_some()
        || asset.state != "uploaded"
        || !(1..=268_435_456).contains(&asset.size)
    {
        return Err(source(
            "GitHub release asset is ambiguous, not uploaded, empty, or exceeds the download limit",
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
    let url = Url::parse(&format!(
        "https://github.com/KDmasterLOL/hostlink/releases/download/{}/{}",
        release.tag_name, name
    ))
    .map_err(|_| source("invalid GitHub asset URL"))?;
    Ok((url, digest.to_ascii_lowercase()))
}

/// Resolve the fixed public repository's latest release or exact `vX.Y.Z` tag.
/// The target must verify the binary before enrollment.
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
    let mut selections = resolve_targets(
        version,
        &[target],
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
        gateway_index,
    )
    .await?;
    Ok(selections.remove(0))
}

/// Resolve every raw executable for a family from the same published release.
/// No invitation is issued by this preflight.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_github_family(
    version: Option<&str>,
    family: OsFamily,
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
    gateway_index: Option<usize>,
) -> Result<Vec<ArtifactSelection>, BootstrapError> {
    resolve_targets(
        version,
        family.targets(),
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
        gateway_index,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_targets(
    version: Option<&str>,
    targets: &[Target],
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
    gateway_index: Option<usize>,
) -> Result<Vec<ArtifactSelection>, BootstrapError> {
    let url = release_url(version)?;
    let client = github_client()?;
    // Public API digest is the fail-closed source of the expected SHA-256; it is not a publisher signature.
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| source("GitHub release request failed or timed out"))?;
    require_ok(response.status())?;
    let bytes = read_bounded(response, MAX_METADATA_BYTES).await?;
    let release = parse_release(&bytes, version)?;
    selections_from_release(
        &release,
        targets,
        name,
        ssh_user,
        hub_url,
        bootstrap_hub_ca_cert,
        gateway_index,
    )
}

#[allow(clippy::too_many_arguments)]
fn selections_from_release(
    release: &Release,
    targets: &[Target],
    name: String,
    ssh_user: String,
    hub_url: String,
    bootstrap_hub_ca_cert: Option<PathBuf>,
    gateway_index: Option<usize>,
) -> Result<Vec<ArtifactSelection>, BootstrapError> {
    targets
        .iter()
        .map(|&target| {
            let (agent_url, agent_sha256) = select_asset(release, &target.asset_name())?;
            let selection = ArtifactSelection {
                agent_url,
                agent_sha256,
                target,
                name: name.clone(),
                ssh_user: ssh_user.clone(),
                hub_url: hub_url.clone(),
                bootstrap_hub_ca_cert: bootstrap_hub_ca_cert.clone(),
                gateway_index,
            };
            selection.validate()?;
            Ok(selection)
        })
        .collect()
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
