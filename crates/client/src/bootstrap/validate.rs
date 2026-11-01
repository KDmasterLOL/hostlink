//! Bootstrap selection data and exact URL, target, version, and identity validation.

use reqwest::Url;
use thiserror::Error;

pub(super) const MAX_INSTALLER_BYTES: usize = 1024 * 1024;
pub(super) const INSTALLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

    pub fn windows(self) -> bool {
        !matches!(self, Self::LinuxX64)
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactSelection {
    pub installer_url: Url,
    pub installer_sha256: String,
    pub agent_url: Url,
    pub agent_sha256: String,
    pub archive_url: Url,
    pub archive_sha256: String,
    pub version: String,
    pub target: Target,
    pub name: String,
    pub ssh_user: String,
    pub hub_url: String,
    pub bootstrap_hub_ca_cert: Option<std::path::PathBuf>,
}

#[derive(Clone, Debug)]
pub struct VerifiedInstaller {
    pub url: Url,
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid bootstrap selection: {0}")]
    Invalid(&'static str),
    #[error("installer source preflight failed: {0}")]
    Source(String),
}

impl ArtifactSelection {
    pub fn validate(&self) -> Result<(), BootstrapError> {
        if !canonical_name(&self.name) {
            return Err(BootstrapError::Invalid(
                "name must be canonical lowercase ASCII",
            ));
        }
        if !ssh_user(&self.ssh_user) {
            return Err(BootstrapError::Invalid("SSH user is invalid"));
        }
        if !semver(&self.version) {
            return Err(BootstrapError::Invalid(
                "exact semantic version is required",
            ));
        }
        for digest in [
            &self.installer_sha256,
            &self.agent_sha256,
            &self.archive_sha256,
        ] {
            if !sha256(digest) {
                return Err(BootstrapError::Invalid(
                    "all artifact SHA-256 pins must be lowercase hexadecimal",
                ));
            }
        }
        let hub = https_url(&self.hub_url)?;
        if hub.path() != "/" || hub.query().is_some() {
            return Err(BootstrapError::Invalid("Hub URL must be an HTTPS origin"));
        }
        // URL paths carry opaque GitHub asset IDs; release names/version and
        // published digests are checked by the authenticated metadata resolver.
        for url in [&self.installer_url, &self.agent_url, &self.archive_url] {
            validate_github_asset_url(url)?;
        }
        if self.installer_url == self.agent_url
            || self.agent_url == self.archive_url
            || self.installer_url == self.archive_url
        {
            return Err(BootstrapError::Invalid(
                "release asset IDs must be distinct",
            ));
        }
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

pub(super) fn validate_installer_contract(
    source: &str,
    target: Target,
) -> Result<(), BootstrapError> {
    let required = if target.windows() {
        [
            "HubUrl",
            "Name",
            "SshUser",
            "AgentUri",
            "AgentSha256",
            "ArchiveUri",
            "ArchiveSha256",
            "AgentVersion",
            "Target",
            "Read-Host",
            "-AsSecureString",
        ]
        .as_slice()
    } else {
        [
            "--hub-url",
            "--name",
            "--ssh-user",
            "--agent-url",
            "--agent-sha256",
            "--archive-url",
            "--archive-sha256",
            "--agent-version",
            "--target",
            "stty -echo",
        ]
        .as_slice()
    };
    if required.iter().any(|part| !source.contains(part)) {
        return Err(BootstrapError::Source(
            "installer does not implement the source-bound enrollment contract".into(),
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
