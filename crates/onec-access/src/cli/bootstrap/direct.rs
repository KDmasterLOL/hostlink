//! Exact direct installer and runtime artifact selection for controller bootstraps.

use super::render::normalized_script_sha256;
use onec_access::{AppResult, HubHttpsUrl};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;

const DIRECT_INSTALLER_MAX_BYTES: usize = 512 * 1024;
pub(super) const WINDOWS_TOOLKIT_BOOTSTRAP: &str =
    include_str!("../../../../onec-agent/assets/Install-OnecToolkit.ps1");

#[derive(Debug, Clone)]
pub(super) struct DirectInstall {
    pub(super) installer_url: HubHttpsUrl,
    pub(super) installer_sha256: String,
    pub(super) package_url: HubHttpsUrl,
    pub(super) package_sha256: String,
    pub(super) package_version: String,
    pub(super) package_target: String,
}

pub(super) async fn validate_direct_install(
    installer_url: &str,
    installer_sha256: &str,
    package_url: &str,
    package_sha256: &str,
    package_version: &str,
    package_target: &str,
) -> AppResult<DirectInstall> {
    let installer_url = HubHttpsUrl::parse(installer_url)?;
    let package_url = HubHttpsUrl::parse(package_url)?;
    let installer_hash = parse_sha256(installer_sha256, "installer SHA-256")?;
    let package_hash = parse_sha256(package_sha256, "package SHA-256")?;
    let embedded_hash = normalized_script_sha256(WINDOWS_TOOLKIT_BOOTSTRAP);
    if !installer_hash.eq_ignore_ascii_case(&embedded_hash) {
        return Err(onec_access::invalid_config(format!(
            "direct installer SHA-256 must match this onec-access binary's pinned Install-OnecToolkit.ps1 ({embedded_hash})"
        )));
    }
    if installer_url.as_url().origin() != package_url.as_url().origin() {
        return Err(onec_access::invalid_config(
            "direct installer script and package URLs must share the same HTTPS origin",
        ));
    }
    if installer_url
        .as_url()
        .path_segments()
        .and_then(Iterator::last)
        != Some("Install-OnecToolkit.ps1")
    {
        return Err(onec_access::invalid_config(
            "direct installer URL must select Install-OnecToolkit.ps1",
        ));
    }
    let expected_package = format!("onec-toolkit-{package_target}.zip");
    if !supported_target(package_target) {
        return Err(onec_access::invalid_config(format!(
            "unsupported direct package target {package_target:?}"
        )));
    }
    if package_url
        .as_url()
        .path_segments()
        .and_then(Iterator::last)
        != Some(expected_package.as_str())
    {
        return Err(onec_access::invalid_config(format!(
            "direct package URL must select {expected_package} for the explicit target"
        )));
    }
    if !valid_package_version(package_version) {
        return Err(onec_access::invalid_config(
            "direct package version must be a plain semantic version such as 1.2.3 or 1.2.3-rc.1",
        ));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(Policy::none())
        .build()
        .map_err(|error| {
            anyhow::anyhow!("failed to create direct artifact preflight client: {error}")
        })?;
    let package_response = client
        .head(package_url.as_url().clone())
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("direct package preflight HEAD failed: {error}"))?;
    if !package_response.status().is_success() || package_response.url() != package_url.as_url() {
        return Err(anyhow::anyhow!(
            "direct package preflight failed or changed URL (HTTP {})",
            package_response.status()
        ));
    }
    validate_direct_package_length(package_response.headers())?;
    let response = client
        .get(installer_url.as_url().clone())
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("direct installer preflight GET failed: {error}"))?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "direct installer preflight returned HTTP {}",
            response.status()
        ));
    }
    if response.url() != installer_url.as_url() {
        return Err(anyhow::anyhow!(
            "direct installer preflight URL changed; redirects are not allowed",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > DIRECT_INSTALLER_MAX_BYTES as u64)
    {
        return Err(anyhow::anyhow!(
            "direct installer script exceeds the {DIRECT_INSTALLER_MAX_BYTES}-byte limit"
        ));
    }
    let mut response = response;
    let mut bytes = Vec::with_capacity(DIRECT_INSTALLER_MAX_BYTES.min(64 * 1024));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow::anyhow!("direct installer script download failed: {error}"))?
    {
        if bytes.len().saturating_add(chunk.len()) > DIRECT_INSTALLER_MAX_BYTES {
            return Err(anyhow::anyhow!(
                "direct installer script exceeds the {DIRECT_INSTALLER_MAX_BYTES}-byte limit"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let script = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("direct installer script is not valid UTF-8"))?;
    let actual = normalized_script_sha256(script);
    if !actual.eq_ignore_ascii_case(&installer_hash) {
        return Err(anyhow::anyhow!(
            "direct installer script SHA-256 mismatch: expected {}, received {actual}",
            installer_hash.to_ascii_lowercase()
        ));
    }

    Ok(DirectInstall {
        installer_url,
        installer_sha256: embedded_hash,
        package_url,
        package_sha256: package_hash,
        package_version: package_version.to_owned(),
        package_target: package_target.to_owned(),
    })
}

fn parse_sha256(value: &str, label: &str) -> AppResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(onec_access::invalid_config(format!(
            "{label} must contain exactly 64 hexadecimal characters"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_direct_package_length(headers: &reqwest::header::HeaderMap) -> AppResult<()> {
    // Response::content_length() measures the decoded response body, which is
    // empty for HEAD even when the server advertises a nonempty archive.
    if let Some(value) = headers.get(reqwest::header::CONTENT_LENGTH) {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("direct package preflight has invalid Content-Length")
            })?;
        if length == 0 || length > 536_870_912 {
            return Err(anyhow::anyhow!(
                "direct package preflight reported an empty or oversized package"
            ));
        }
    }
    Ok(())
}

fn supported_target(value: &str) -> bool {
    matches!(
        value,
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc" | "i686-win7-windows-msvc"
    )
}

fn valid_package_version(value: &str) -> bool {
    semver::Version::parse(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_package_head_uses_header_length_not_empty_head_body() {
        use reqwest::header::{CONTENT_LENGTH, HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        validate_direct_package_length(&headers).unwrap();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("18081703"));
        validate_direct_package_length(&headers).unwrap();
        for value in ["0", "536870913", "not-a-number", "-1"] {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
            assert!(validate_direct_package_length(&headers).is_err(), "{value}");
        }
    }

    fn valid_inputs() -> (&'static str, String, &'static str, String) {
        (
            "https://downloads.example.test/Install-OnecToolkit.ps1",
            normalized_script_sha256(WINDOWS_TOOLKIT_BOOTSTRAP),
            "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            "a".repeat(64),
        )
    }

    #[tokio::test]
    async fn direct_installer_rejects_wrong_pinned_script_hash_before_network() {
        let (script_url, _, package_url, package_hash) = valid_inputs();
        let error = validate_direct_install(
            script_url,
            &"b".repeat(64),
            package_url,
            &package_hash,
            "1.2.3",
            "x86_64-win7-windows-msvc",
        )
        .await
        .expect_err("wrong script pin must fail before network access");
        assert!(error.to_string().contains("pinned Install-OnecToolkit.ps1"));
    }

    #[tokio::test]
    async fn direct_installer_rejects_unsafe_or_foreign_artifact_urls() {
        let (_, script_hash, _, package_hash) = valid_inputs();
        for (script_url, package_url) in [
            (
                "http://downloads.example.test/Install-OnecToolkit.ps1",
                "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            ),
            (
                "https://user:pass@downloads.example.test/Install-OnecToolkit.ps1",
                "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            ),
            (
                "https://downloads.example.test/Install-OnecToolkit.ps1",
                "https://foreign.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            ),
        ] {
            assert!(
                validate_direct_install(
                    script_url,
                    &script_hash,
                    package_url,
                    &package_hash,
                    "1.2.3",
                    "x86_64-win7-windows-msvc",
                )
                .await
                .is_err(),
                "unsafe direct URL pair must fail before the preflight request"
            );
        }
    }

    #[test]
    fn direct_installer_rejects_incomplete_sha_version_and_target_bindings() {
        assert!(parse_sha256("abc", "package SHA-256").is_err());
        assert!(!valid_package_version("1.2"));
        assert!(!valid_package_version("1.2.3+"));
        assert!(!valid_package_version("01.2.3"));
        assert!(!valid_package_version("1.02.3"));
        assert!(!valid_package_version("1.2.03"));
        assert!(!valid_package_version("1.2.3-01"));
        assert!(!valid_package_version("1.2.3.4"));
        assert!(!valid_package_version("1.2.3;Invoke-Expression"));
        assert!(!supported_target("x86_64-unknown-linux-gnu"));
    }
}
