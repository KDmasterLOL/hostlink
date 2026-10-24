//! Exact direct installer and runtime artifact selection for controller bootstraps.

use super::render::normalized_script_sha256;
use hostlink_access::{AppResult, HubHttpsUrl};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;

const DIRECT_INSTALLER_MAX_BYTES: usize = 512 * 1024;
const DIRECT_AGENT_EXECUTABLE_MAX_BYTES: u64 = 268_435_456;
pub(super) const HOSTLINK_AGENT_BOOTSTRAP: &str =
    include_str!("../../../../onec-agent/assets/Install-HostLink-Agent.ps1");

#[derive(Debug, Clone)]
pub(super) struct DirectInstall {
    pub(super) installer_url: HubHttpsUrl,
    pub(super) installer_sha256: String,
    pub(super) package_url: HubHttpsUrl,
    pub(super) package_sha256: String,
    pub(super) package_version: String,
    pub(super) package_target: String,
    pub(super) agent_executable_url: Option<HubHttpsUrl>,
    pub(super) agent_executable_sha256: Option<String>,
}

pub(super) async fn validate_direct_install(
    installer_url: &str,
    installer_sha256: &str,
    package_url: &str,
    package_sha256: &str,
    package_version: &str,
    package_target: &str,
    agent_executable: (Option<&str>, Option<&str>),
) -> AppResult<DirectInstall> {
    let installer_url = HubHttpsUrl::parse(installer_url)?;
    let package_url = HubHttpsUrl::parse(package_url)?;
    let installer_hash = parse_sha256(installer_sha256, "installer SHA-256")?;
    let package_hash = parse_sha256(package_sha256, "package SHA-256")?;
    let win7_target = matches!(
        package_target,
        "x86_64-win7-windows-msvc" | "i686-win7-windows-msvc"
    );
    let (agent_executable_url, agent_executable_hash) = match agent_executable {
        (Some(url), Some(hash)) => {
            let url = HubHttpsUrl::parse(url)?;
            let hash = parse_sha256(hash, "Agent executable SHA-256")?;
            if url.as_url().query().is_some() || url.as_url().fragment().is_some() {
                return Err(hostlink_access::invalid_config(
                    "direct Agent executable URL must not contain a query or fragment",
                ));
            }
            if url.as_url().origin() != package_url.as_url().origin()
                || url.as_url().origin() != installer_url.as_url().origin()
            {
                return Err(hostlink_access::invalid_config(
                    "direct Agent executable, installer script, and package URLs must share the same HTTPS origin",
                ));
            }
            let path_segments = url
                .as_url()
                .path_segments()
                .map(|segments| segments.collect::<Vec<_>>())
                .unwrap_or_default();
            let segment_count = path_segments.len();
            if segment_count < 2
                || path_segments[segment_count - 2] != package_target
                || path_segments[segment_count - 1] != "hostlink-agent.exe"
            {
                return Err(hostlink_access::invalid_config(format!(
                    "direct Agent executable URL must end in /{package_target}/hostlink-agent.exe"
                )));
            }
            (Some(url), Some(hash))
        }
        (None, None) if !win7_target => (None, None),
        (None, None) => {
            return Err(hostlink_access::invalid_config(
                "Win7 direct package targets require --direct-agent-executable-url and --direct-agent-executable-sha256; no invite token was created",
            ));
        }
        _ => {
            return Err(hostlink_access::invalid_config(
                "--direct-agent-executable-url and --direct-agent-executable-sha256 must be provided together",
            ));
        }
    };
    let embedded_hash = normalized_script_sha256(HOSTLINK_AGENT_BOOTSTRAP);
    if !installer_hash.eq_ignore_ascii_case(&embedded_hash) {
        return Err(hostlink_access::invalid_config(format!(
            "direct installer SHA-256 must match this hostlink binary's pinned Install-HostLink-Agent.ps1 ({embedded_hash})"
        )));
    }
    if installer_url.as_url().origin() != package_url.as_url().origin() {
        return Err(hostlink_access::invalid_config(
            "direct installer script and package URLs must share the same HTTPS origin",
        ));
    }
    if installer_url
        .as_url()
        .path_segments()
        .and_then(Iterator::last)
        != Some("Install-HostLink-Agent.ps1")
    {
        return Err(hostlink_access::invalid_config(
            "direct installer URL must select Install-HostLink-Agent.ps1",
        ));
    }
    let expected_package = format!("hostlink-agent-{package_target}.zip");
    if !supported_target(package_target) {
        return Err(hostlink_access::invalid_config(format!(
            "unsupported direct package target {package_target:?}"
        )));
    }
    if package_url
        .as_url()
        .path_segments()
        .and_then(Iterator::last)
        != Some(expected_package.as_str())
    {
        return Err(hostlink_access::invalid_config(format!(
            "direct package URL must select {expected_package} for the explicit target"
        )));
    }
    if !valid_package_version(package_version) {
        return Err(hostlink_access::invalid_config(
            "direct package version must be a plain semantic version such as 1.2.3 or 1.2.3-rc.1",
        ));
    }
    validate_agent_enrollment_installer(HOSTLINK_AGENT_BOOTSTRAP, agent_executable_url.is_some())?;

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
    if let Some(url) = &agent_executable_url {
        let response = client
            .head(url.as_url().clone())
            .send()
            .await
            .map_err(|error| {
                anyhow::anyhow!("direct Agent executable preflight HEAD failed: {error}")
            })?;
        if !response.status().is_success() || response.url() != url.as_url() {
            return Err(anyhow::anyhow!(
                "direct Agent executable preflight failed or changed URL (HTTP {})",
                response.status()
            ));
        }
        validate_direct_agent_executable_length(response.headers())?;
    }
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
        .is_none_or(|length| length == 0 || length > DIRECT_INSTALLER_MAX_BYTES as u64)
    {
        return Err(anyhow::anyhow!(
            "direct installer script has an invalid or excessive declared size"
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
        agent_executable_url,
        agent_executable_sha256: agent_executable_hash,
    })
}

fn validate_agent_enrollment_installer(
    script: &str,
    requires_agent_executable: bool,
) -> AppResult<()> {
    if !script.contains("HubUrl") || !script.contains("EnrollmentTokenFile") {
        return Err(hostlink_access::invalid_config(
            "embedded Install-HostLink-Agent.ps1 does not support the pinned HostLink enrollment contract; no invite token was created",
        ));
    }
    if requires_agent_executable
        && (!script.contains("AgentExecutableFile") || !script.contains("AgentExecutableSha256"))
    {
        return Err(hostlink_access::invalid_config(
            "embedded Install-HostLink-Agent.ps1 does not support the pinned Agent executable sidecar contract; no invite token was created",
        ));
    }
    Ok(())
}

fn parse_sha256(value: &str, label: &str) -> AppResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(hostlink_access::invalid_config(format!(
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
    } else {
        return Err(anyhow::anyhow!(
            "direct package preflight did not report Content-Length"
        ));
    }
    Ok(())
}

fn validate_direct_agent_executable_length(headers: &reqwest::header::HeaderMap) -> AppResult<()> {
    let length = headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("direct Agent executable preflight requires a valid Content-Length")
        })?;
    if !(1..=DIRECT_AGENT_EXECUTABLE_MAX_BYTES).contains(&length) {
        return Err(anyhow::anyhow!(
            "direct Agent executable must be between 1 and {DIRECT_AGENT_EXECUTABLE_MAX_BYTES} bytes"
        ));
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
        assert!(validate_direct_package_length(&headers).is_err());
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("18081703"));
        validate_direct_package_length(&headers).unwrap();
        for value in ["0", "536870913", "not-a-number", "-1"] {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
            assert!(validate_direct_package_length(&headers).is_err(), "{value}");
        }
    }

    fn valid_inputs() -> (&'static str, String, &'static str, String) {
        (
            "https://downloads.example.test/Install-HostLink-Agent.ps1",
            normalized_script_sha256(HOSTLINK_AGENT_BOOTSTRAP),
            "https://downloads.example.test/hostlink-agent-x86_64-win7-windows-msvc.zip",
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
            (
                Some("https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe"),
                Some(&"a".repeat(64)),
            ),
        )
        .await
        .expect_err("wrong script pin must fail before network access");
        assert!(
            error
                .to_string()
                .contains("pinned Install-HostLink-Agent.ps1")
        );
    }

    #[tokio::test]
    async fn direct_installer_rejects_unsafe_or_foreign_artifact_urls() {
        let (_, script_hash, _, package_hash) = valid_inputs();
        for (script_url, package_url) in [
            (
                "http://downloads.example.test/Install-HostLink-Agent.ps1",
                "https://downloads.example.test/hostlink-agent-x86_64-win7-windows-msvc.zip",
            ),
            (
                "https://user:pass@downloads.example.test/Install-HostLink-Agent.ps1",
                "https://downloads.example.test/hostlink-agent-x86_64-win7-windows-msvc.zip",
            ),
            (
                "https://downloads.example.test/Install-HostLink-Agent.ps1",
                "https://foreign.example.test/hostlink-agent-x86_64-win7-windows-msvc.zip",
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
                    (
                        Some("https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe"),
                        Some(&"a".repeat(64)),
                    ),
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

    #[test]
    fn direct_agent_executable_head_requires_bounded_content_length() {
        use reqwest::header::{CONTENT_LENGTH, HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        assert!(validate_direct_agent_executable_length(&headers).is_err());
        for value in ["0", "268435457", "not-a-number"] {
            headers.insert(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
            assert!(
                validate_direct_agent_executable_length(&headers).is_err(),
                "{value}"
            );
        }
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("268435456"));
        validate_direct_agent_executable_length(&headers).unwrap();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        validate_direct_agent_executable_length(&headers).unwrap();
    }

    #[tokio::test]
    async fn win7_sidecar_contract_rejects_missing_pairs_and_unsafe_urls_before_network() {
        let (script_url, script_hash, package_url, package_hash) = valid_inputs();
        let base = |sidecar_url, sidecar_hash| {
            validate_direct_install(
                script_url,
                &script_hash,
                package_url,
                &package_hash,
                "1.2.3",
                "x86_64-win7-windows-msvc",
                (sidecar_url, sidecar_hash),
            )
        };
        assert!(
            base(None, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("require")
        );
        assert!(
            base(
                Some("https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe"),
                None
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("provided together")
        );
        let valid_hash = "a".repeat(64);
        assert!(
            base(None, Some(&valid_hash))
                .await
                .unwrap_err()
                .to_string()
                .contains("provided together")
        );
        for url in [
            "http://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe",
            "https://user:pass@downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe",
            "https://foreign.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe",
            "https://downloads.example.test/x86_64-win7-windows-msvc/not-agent.exe",
            "https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe?redirect=1",
            "https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe#fragment",
        ] {
            assert!(base(Some(url), Some(&valid_hash)).await.is_err(), "{url}");
        }
        let cross_target =
            "https://downloads.example.test/i686-win7-windows-msvc/hostlink-agent.exe";
        let error = base(Some(cross_target), Some(&valid_hash))
            .await
            .expect_err("sidecar target must match the package target before preflight");
        assert!(
            error
                .to_string()
                .contains("/x86_64-win7-windows-msvc/hostlink-agent.exe")
        );
        assert!(
            base(
                Some("https://downloads.example.test/x86_64-win7-windows-msvc/hostlink-agent.exe"),
                Some("bad-hash"),
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn direct_installer_requires_the_agent_owned_enrollment_parameters() {
        assert!(validate_agent_enrollment_installer("param($ConfigFile)", false).is_err());
        validate_agent_enrollment_installer(
            "param([string]$HubUrl,[string]$EnrollmentTokenFile)",
            false,
        )
        .expect("agent installer must expose both agreed enrollment parameters");
        assert!(
            validate_agent_enrollment_installer(
                "param([string]$HubUrl,[string]$EnrollmentTokenFile)",
                true
            )
            .is_err()
        );
        validate_agent_enrollment_installer(
            "param([string]$HubUrl,[string]$EnrollmentTokenFile,[string]$AgentExecutableFile,[string]$AgentExecutableSha256)",
            true,
        )
        .expect("Win7 Agent installer must expose both sidecar parameters");
    }
}
