//! Authenticated installer preflight; one credential-free GitHub CDN hop at most.

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
    #[cfg(test)]
    if selection.installer_url.host_str() == Some("artifacts.example") {
        return verify_fixture_installer(selection, hub_ca_cert).await;
    }
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
        if let Some(location) = installer_redirect(&response)? {
            // No default Authorization and no automatic redirects/proxy. Never
            // clone the authenticated request, even for a GitHub-owned CDN.
            response = cdn_get(&client, &location)?
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

fn installer_redirect(response: &reqwest::Response) -> Result<Option<String>, BootstrapError> {
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
    github_cdn_url(location)?;
    Ok(Some(location.to_owned()))
}

fn cdn_get(
    client: &reqwest::Client,
    location: &str,
) -> Result<reqwest::RequestBuilder, BootstrapError> {
    Ok(client
        .get(github_cdn_url(location)?)
        .header(reqwest::header::ACCEPT, "application/octet-stream")
        .header(reqwest::header::ACCEPT_ENCODING, "identity"))
}

fn github_cdn_url(location: &str) -> Result<Url, BootstrapError> {
    if location.len() > 8192 {
        return Err(BootstrapError::Invalid("GitHub redirect URL exceeds limit"));
    }
    let url = parse_artifact_url(location)?;
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
    Ok(url)
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
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(BootstrapError::Source(
            "GitHub source exceeds the byte limit".into(),
        ));
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

// Existing arbitrary-origin installer fixtures are never compiled in production.
#[cfg(test)]
pub(super) async fn fetch_bytes(client: &reqwest::Client, url: Url) -> Result<Vec<u8>, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "HTTPS request failed".to_owned())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("installer source did not return HTTP 200 without redirects".into());
    }
    read_bounded(response, MAX_INSTALLER_BYTES)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
async fn verify_fixture_installer(
    selection: &ArtifactSelection,
    ca: Option<&std::path::Path>,
) -> Result<VerifiedInstaller, BootstrapError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(INSTALLER_TIMEOUT);
    if let Some(path) = ca {
        builder =
            builder.add_root_certificate(crate::hub::read_ca_certificate(path).map_err(|_| {
                BootstrapError::Source("configured Hub CA is unsafe or invalid".into())
            })?);
    }
    let client = builder
        .build()
        .map_err(|_| BootstrapError::Source("could not create HTTPS fixture client".into()))?;
    let bytes = fetch_bytes(&client, selection.installer_url.clone())
        .await
        .map_err(BootstrapError::Source)?;
    let sha256 = validate_installer_bytes(&bytes, &selection.installer_sha256, selection.target)?;
    Ok(VerifiedInstaller {
        url: selection.installer_url.clone(),
        sha256,
    })
}

#[cfg(test)]
mod github_tests {
    use super::*;

    #[test]
    fn cdn_request_never_contains_credentials_and_rejects_other_origins() {
        let client = super::super::github::github_client().unwrap();
        for host in [
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
            "github-releases.githubusercontent.com",
        ] {
            let request = cdn_get(&client, &format!("https://{host}/asset?signed=fixture"))
                .unwrap()
                .build()
                .unwrap();
            assert!(
                !request
                    .headers()
                    .contains_key(reqwest::header::AUTHORIZATION)
            );
            assert_eq!(
                request.headers()[reqwest::header::ACCEPT],
                "application/octet-stream"
            );
        }
        for invalid in [
            "http://release-assets.githubusercontent.com/asset",
            "https://api.github.com/asset",
            "https://github.com/asset",
            "https://release-assets.githubusercontent.com.evil.invalid/a",
            "https://user@objects.githubusercontent.com/asset",
            "https://objects.githubusercontent.com:444/asset",
            "https://objects.githubusercontent.com/asset#fragment",
            "/relative",
        ] {
            assert!(cdn_get(&client, invalid).is_err());
        }
        assert!(
            cdn_get(
                &client,
                &format!("https://objects.githubusercontent.com/{}", "a".repeat(8192))
            )
            .is_err()
        );
    }
    #[test]
    fn installer_accepts_only_200_or_one_valid_302() {
        use axum::http::Response;
        let direct =
            reqwest::Response::from(Response::builder().status(200).body("installer").unwrap());
        assert!(installer_redirect(&direct).unwrap().is_none());
        let location = "https://release-assets.githubusercontent.com/asset?signed=fixture";
        let redirect = reqwest::Response::from(
            Response::builder()
                .status(302)
                .header("location", location)
                .body("")
                .unwrap(),
        );
        assert_eq!(
            installer_redirect(&redirect).unwrap().as_deref(),
            Some(location)
        );
        // After the single hop the production path requires HTTP200, never loops.
        assert!(super::super::github::require_ok(redirect.status()).is_err());
        let missing = reqwest::Response::from(Response::builder().status(302).body("").unwrap());
        assert!(installer_redirect(&missing).is_err());
        let duplicate = reqwest::Response::from(
            Response::builder()
                .status(302)
                .header("location", location)
                .header("location", location)
                .body("")
                .unwrap(),
        );
        assert!(installer_redirect(&duplicate).is_err());
        for status in [301, 303, 307, 308, 401, 403, 404, 500] {
            let response =
                reqwest::Response::from(Response::builder().status(status).body("").unwrap());
            assert!(installer_redirect(&response).is_err());
        }
    }

    #[tokio::test]
    async fn bounded_read_checks_declared_and_actual_size_and_encoding() {
        use axum::http::Response;
        let exact = reqwest::Response::from(Response::builder().body("1234").unwrap());
        assert_eq!(read_bounded(exact, 4).await.unwrap(), b"1234");
        let oversized = reqwest::Response::from(Response::builder().body("12345").unwrap());
        assert!(read_bounded(oversized, 4).await.is_err());
        let declared = reqwest::Response::from(
            Response::builder()
                .header("content-length", "5")
                .body("")
                .unwrap(),
        );
        assert!(read_bounded(declared, 4).await.is_err());
        let encoded = reqwest::Response::from(
            Response::builder()
                .header("content-encoding", "gzip")
                .body("1234")
                .unwrap(),
        );
        assert!(read_bounded(encoded, 4).await.is_err());
    }
}
