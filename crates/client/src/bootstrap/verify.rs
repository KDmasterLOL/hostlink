//! Source-pinned installer preflight with bounded, redirect-free HTTPS reads.

use reqwest::Url;
use sha2::{Digest, Sha256};

use super::validate::{
    ArtifactSelection, BootstrapError, INSTALLER_TIMEOUT, MAX_INSTALLER_BYTES, Target,
    VerifiedInstaller, validate_https_url, validate_installer_contract, validate_path,
};

pub fn parse_artifact_url(value: &str) -> Result<Url, BootstrapError> {
    let Some(scheme_end) = value.find("://") else {
        return Err(BootstrapError::Invalid("malformed HTTPS URL"));
    };
    let authority_and_path = &value[scheme_end + 3..];
    let first_suffix = authority_and_path.find(['/', '\\', '?', '#']);
    let authority_end = first_suffix.unwrap_or(authority_and_path.len());
    if authority_and_path[..authority_end].contains('@') {
        return Err(BootstrapError::Invalid(
            "artifact URLs must not contain user information",
        ));
    }
    if let Some(path_start) =
        first_suffix.filter(|index| matches!(authority_and_path.as_bytes()[*index], b'/' | b'\\'))
    {
        let path_and_suffix = &authority_and_path[path_start..];
        let path_end = path_and_suffix
            .find(['?', '#'])
            .unwrap_or(path_and_suffix.len());
        validate_path(&path_and_suffix[..path_end])?;
    }
    let url = Url::parse(value).map_err(|_| BootstrapError::Invalid("malformed HTTPS URL"))?;
    validate_https_url(&url)?;
    Ok(url)
}

pub async fn verify_installer(
    selection: &ArtifactSelection,
    hub_ca_cert: Option<&std::path::Path>,
) -> Result<VerifiedInstaller, BootstrapError> {
    selection.validate()?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(INSTALLER_TIMEOUT);
    if let Some(path) = hub_ca_cert {
        // Reuse HubClient's bounded no-follow CA loader. A caller-controlled
        // path must not permit an unbounded read or an unexpected symlink
        // when selecting an HTTPS trust root for installer preflight.
        builder =
            builder.add_root_certificate(crate::hub::read_ca_certificate(path).map_err(|_| {
                BootstrapError::Source("configured Hub CA is unsafe or invalid".into())
            })?);
    }
    let client = builder
        .build()
        .map_err(|_| BootstrapError::Source("could not create HTTPS client".into()))?;
    let bytes = fetch_bytes(&client, selection.installer_url.clone())
        .await
        .map_err(BootstrapError::Source)?;
    let actual = validate_installer_bytes(&bytes, &selection.installer_sha256, selection.target)?;
    Ok(VerifiedInstaller {
        url: selection.installer_url.clone(),
        sha256: actual,
    })
}

pub(super) fn validate_installer_bytes(
    bytes: &[u8],
    expected_sha256: &str,
    target: Target,
) -> Result<String, BootstrapError> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected_sha256 {
        return Err(BootstrapError::Source(
            "installer SHA-256 does not match the independent pin".into(),
        ));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| BootstrapError::Source("installer is not valid UTF-8".into()))?;
    validate_installer_contract(source, target)?;
    Ok(actual)
}

pub(super) async fn fetch_bytes(client: &reqwest::Client, url: Url) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| "HTTPS request failed or certificate validation failed".to_owned())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("installer source did not return HTTP 200 without redirects".into());
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err("installer source used an unexpected content encoding".into());
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_INSTALLER_BYTES as u64)
    {
        return Err("installer source exceeds the byte limit".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "installer download failed".to_owned())?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_INSTALLER_BYTES {
            return Err("installer source exceeds the byte limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
