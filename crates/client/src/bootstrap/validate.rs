//! Bootstrap selection data and exact URL, target, version, and identity validation.

use reqwest::Url;
use std::{error::Error, fmt};

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

#[derive(Debug)]
pub enum BootstrapError {
    Invalid(&'static str),
    Source(String),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid bootstrap selection: {message}"),
            Self::Source(message) => write!(f, "installer source preflight failed: {message}"),
        }
    }
}

impl Error for BootstrapError {}

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
        let urls = [&self.installer_url, &self.agent_url, &self.archive_url];
        for url in urls {
            validate_https_url(url)?;
            if origin(url) != origin(&self.installer_url) {
                return Err(BootstrapError::Invalid(
                    "installer, sidecar, and ZIP must share the approved HTTPS origin",
                ));
            }
        }
        let expected_archive = format!("hostlink-agent-{}.zip", self.target.as_str());
        if self.archive_url.path_segments().and_then(Iterator::last)
            != Some(expected_archive.as_str())
        {
            return Err(BootstrapError::Invalid(
                "ZIP URL must name the exact selected target",
            ));
        }
        let agent_segments = self
            .agent_url
            .path_segments()
            .ok_or(BootstrapError::Invalid("sidecar URL path is invalid"))?
            .collect::<Vec<_>>();
        let agent_name = agent_segments.last().copied().unwrap_or_default();
        let expected_agent = if self.target.windows() {
            "hostlink-agent.exe"
        } else {
            "hostlink-agent"
        };
        if agent_name != expected_agent
            || !agent_segments[..agent_segments.len().saturating_sub(1)]
                .contains(&self.target.as_str())
            || !has_version_segment(&agent_segments, &self.version)
        {
            return Err(BootstrapError::Invalid(
                "sidecar URL must bind the selected version and target-specific Agent executable",
            ));
        }
        let archive_segments = self
            .archive_url
            .path_segments()
            .ok_or(BootstrapError::Invalid("ZIP URL path is invalid"))?
            .collect::<Vec<_>>();
        if !has_version_segment(&archive_segments, &self.version) {
            return Err(BootstrapError::Invalid(
                "ZIP URL must bind the exact selected version",
            ));
        }
        Ok(())
    }
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
    let has_userinfo = value
        .as_str()
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'));
    if value.scheme() != "https"
        || value.host_str().is_none()
        || has_userinfo
        || value.password().is_some()
        || value.fragment().is_some()
    {
        return Err(BootstrapError::Invalid(
            "artifact URLs must be credential-free HTTPS URLs without fragments",
        ));
    }
    validate_path(value.path())?;
    Ok(())
}

pub(super) fn validate_path(path: &str) -> Result<(), BootstrapError> {
    if path.contains('\\') {
        return Err(BootstrapError::Invalid("artifact URL path is unsafe"));
    }
    for segment in path.split('/') {
        let bytes = segment.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let Some(hex) = bytes.get(index + 1..index + 3) else {
                    return Err(BootstrapError::Invalid("artifact URL path is unsafe"));
                };
                let high = (hex[0] as char).to_digit(16);
                let low = (hex[1] as char).to_digit(16);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(BootstrapError::Invalid("artifact URL path is unsafe"));
                };
                decoded.push(((high << 4) | low) as u8);
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        if decoded == b"."
            || decoded == b".."
            || decoded.contains(&b'/')
            || decoded.contains(&b'\\')
            || decoded.contains(&b'%')
        {
            return Err(BootstrapError::Invalid("artifact URL path is unsafe"));
        }
    }
    Ok(())
}

pub(super) fn https_url(value: &str) -> Result<Url, BootstrapError> {
    let url = Url::parse(value).map_err(|_| BootstrapError::Invalid("malformed HTTPS URL"))?;
    validate_https_url(&url)?;
    Ok(url)
}

pub(super) fn origin(url: &Url) -> (String, String, Option<u16>) {
    (
        url.scheme().to_owned(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port(),
    )
}

pub(super) fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn semver(value: &str) -> bool {
    let (before_build, build) = match value.split_once('+') {
        Some((left, right)) => (left, Some(right)),
        None => (value, None),
    };
    if let Some(build) = build
        && (build.is_empty() || !build.split('.').all(identifier))
    {
        return false;
    }
    let (core, prerelease) = match before_build.split_once('-') {
        Some((left, right)) => (left, Some(right)),
        None => (before_build, None),
    };
    if let Some(prerelease) = prerelease
        && (prerelease.is_empty()
            || !prerelease.split('.').all(|part| {
                identifier(part)
                    && !(part.bytes().all(|byte| byte.is_ascii_digit())
                        && part.len() > 1
                        && part.starts_with('0'))
            }))
    {
        return false;
    }
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

pub(super) fn canonical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn has_version_segment(segments: &[&str], version: &str) -> bool {
    segments
        .iter()
        .any(|segment| *segment == version || *segment == format!("v{version}"))
}

pub(super) fn ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
