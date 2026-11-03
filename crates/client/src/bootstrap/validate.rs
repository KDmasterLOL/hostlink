//! Bootstrap selection data and exact URL, target, version, and identity validation.

use reqwest::Url;
use thiserror::Error;

pub(super) const METADATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Win7X86,
    Win7X64,
    Win11X64,
    LinuxX64,
}

impl Target {
    pub fn parse(value: &str) -> Result<Self, BootstrapError> {
        match value {
            "i686-win7-windows-msvc" => Ok(Self::Win7X86),
            "x86_64-win7-windows-msvc" => Ok(Self::Win7X64),
            "x86_64-pc-windows-msvc" => Ok(Self::Win11X64),
            "x86_64-unknown-linux-gnu" => Ok(Self::LinuxX64),
            _ => Err(BootstrapError::Invalid("unsupported bootstrap target")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Win7X86 => "i686-win7-windows-msvc",
            Self::Win7X64 => "x86_64-win7-windows-msvc",
            Self::Win11X64 => "x86_64-pc-windows-msvc",
            Self::LinuxX64 => "x86_64-unknown-linux-gnu",
        }
    }

    pub fn asset_name(self) -> String {
        format!(
            "hostlink-agent-{}{}",
            self.as_str(),
            if self.windows() { ".exe" } else { "" }
        )
    }

    pub fn windows(self) -> bool {
        !matches!(self, Self::LinuxX64)
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactSelection {
    // Only the authenticated GitHub resolver may issue a selection to callers.
    // Rendering a caller-built set of untrusted URL/digest fields bypasses that
    // ownership boundary even if the target-side downloader fails closed.
    pub(super) agent_url: Url,
    pub(super) agent_sha256: String,
    pub(super) target: Target,
    pub(super) name: String,
    pub(super) ssh_user: String,
    pub(super) hub_url: String,
    pub(super) bootstrap_hub_ca_cert: Option<std::path::PathBuf>,
    pub(super) gateway_index: Option<usize>,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid bootstrap selection: {0}")]
    Invalid(&'static str),
    #[error("GitHub release selection failed: {0}")]
    Source(String),
}

impl ArtifactSelection {
    /// Verified GitHub-published digest associated with the selected executable.
    pub fn agent_sha256(&self) -> &str {
        &self.agent_sha256
    }

    pub(super) fn validate(&self) -> Result<(), BootstrapError> {
        if !canonical_name(&self.name) {
            return Err(BootstrapError::Invalid(
                "name must be canonical lowercase ASCII",
            ));
        }
        if !ssh_user(&self.ssh_user) {
            return Err(BootstrapError::Invalid("SSH user is invalid"));
        }
        if !sha256(&self.agent_sha256) {
            return Err(BootstrapError::Invalid(
                "binary SHA-256 pin must be lowercase hexadecimal",
            ));
        }
        let hub = https_url(&self.hub_url)?;
        if hub.path() != "/" || hub.query().is_some() {
            return Err(BootstrapError::Invalid("Hub URL must be an HTTPS origin"));
        }
        // URL paths carry opaque GitHub asset IDs; release names/version and
        // published digests are checked by the authenticated metadata resolver.
        validate_github_asset_url(&self.agent_url)?;
        Ok(())
    }
}

pub(super) fn validate_github_asset_url(url: &Url) -> Result<(), BootstrapError> {
    validate_https_url(url)?;
    let id = url
        .path()
        .strip_prefix("/repos/KDmasterLOL/hostlink/releases/assets/");
    if url.host_str() != Some("api.github.com")
        || url.port().is_some()
        || url.query().is_some()
        || !id.is_some_and(|id| {
            id.bytes().all(|byte| byte.is_ascii_digit()) && id.parse::<u64>().is_ok_and(|id| id > 0)
        })
    {
        return Err(BootstrapError::Invalid(
            "exact credential-free KDmasterLOL/hostlink GitHub API asset URL required",
        ));
    }
    Ok(())
}

pub(super) fn validate_https_url(value: &Url) -> Result<(), BootstrapError> {
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.fragment().is_some()
    {
        return Err(BootstrapError::Invalid(
            "artifact URLs must be credential-free HTTPS URLs without fragments",
        ));
    }
    Ok(())
}

pub(super) fn https_url(value: &str) -> Result<Url, BootstrapError> {
    let url = Url::parse(value).map_err(|_| BootstrapError::Invalid("malformed HTTPS URL"))?;
    validate_https_url(&url)?;
    Ok(url)
}

pub(super) fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn semver(value: &str) -> bool {
    semver::Version::parse(value).is_ok()
}

pub(super) fn canonical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

pub(super) fn ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
