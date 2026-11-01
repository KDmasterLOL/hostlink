//! Authenticated installer preflight; one credential-free GitHub CDN hop at most.

use reqwest::{Client, RequestBuilder};
use sha2::{Digest, Sha256};

use super::validate::{
    ArtifactSelection, BootstrapError, INSTALLER_TIMEOUT, MAX_INSTALLER_BYTES, Target,
    VerifiedInstaller, https_url, validate_installer_contract,
};

pub async fn verify_installer(
    selection: &ArtifactSelection,
    hub_ca_cert: Option<&std::path::Path>,
) -> Result<VerifiedInstaller, BootstrapError> {
    selection.validate()?;
    // Hub's private CA is unrelated to GitHub; use public trust roots for GitHub.
    if let Some(path) = hub_ca_cert {
        crate::hub::read_ca_certificate(path)
            .map_err(|_| BootstrapError::Source("configured Hub CA is unsafe or invalid".into()))?;
    }
    let token = super::github::read_token()?;
    let client = super::github::github_client()?;
    let bytes = tokio::time::timeout(INSTALLER_TIMEOUT, async {
        let mut response = super::github::authenticated_get(
            &client,
            selection.installer_url.clone(),
            &token,
            "application/octet-stream",
        )?
        .send()
        .await
        .map_err(|_| BootstrapError::Source("GitHub installer request failed".into()))?;
        if let Some(request) = installer_redirect(&client, &response)? {
            // No default Authorization and no automatic redirects/proxy. Never
            // clone the authenticated request, even for a GitHub-owned CDN.
            response = request
                .send()
                .await
                .map_err(|_| BootstrapError::Source("GitHub CDN request failed".into()))?;
        }
        super::github::require_ok(response.status())?;
        read_bounded(response, MAX_INSTALLER_BYTES).await
    })
    .await
    .map_err(|_| {
        BootstrapError::Source("GitHub installer preflight exceeded 30 seconds".into())
    })??;
    let actual = validate_installer_bytes(&bytes, &selection.installer_sha256, selection.target)?;
    Ok(VerifiedInstaller {
        url: selection.installer_url.clone(),
        sha256: actual,
    })
}

pub(super) fn installer_redirect(
    client: &Client,
    response: &reqwest::Response,
) -> Result<Option<RequestBuilder>, BootstrapError> {
    if response.status() != reqwest::StatusCode::FOUND {
        super::github::require_ok(response.status())?;
        return Ok(None);
    }
    let mut locations = response.headers().get_all(reqwest::header::LOCATION).iter();
    let location = locations
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(BootstrapError::Invalid(
            "GitHub asset redirect lacks a valid Location",
        ))?;
    if locations.next().is_some() {
        return Err(BootstrapError::Invalid("ambiguous GitHub asset redirect"));
    }
    if location.len() > 8192 {
        return Err(BootstrapError::Invalid("GitHub redirect URL exceeds limit"));
    }
    let url = https_url(location)?;
    if url.port().is_some()
        || !matches!(
            url.host_str(),
            Some(
                "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
                    | "github-releases.githubusercontent.com"
            )
        )
    {
        return Err(BootstrapError::Invalid(
            "GitHub asset redirect must use an approved HTTPS GitHub CDN",
        ));
    }
    Ok(Some(
        client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .header(reqwest::header::ACCEPT_ENCODING, "identity"),
    ))
}

pub(super) fn validate_installer_bytes(
    bytes: &[u8],
    expected_sha256: &str,
    target: Target,
) -> Result<String, BootstrapError> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected_sha256 {
        return Err(BootstrapError::Source(
            "installer SHA-256 does not match the authenticated GitHub digest".into(),
        ));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| BootstrapError::Source("installer is not valid UTF-8".into()))?;
    validate_installer_contract(source, target)?;
    Ok(actual)
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
