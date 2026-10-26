//! Source-pinned invitation installer selection and copyable bootstrap rendering.

use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const MAX_INSTALLER_BYTES: usize = 1024 * 1024;
const INSTALLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

fn validate_installer_bytes(
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

async fn fetch_bytes(client: &reqwest::Client, url: Url) -> Result<Vec<u8>, String> {
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

pub fn render_command(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
    if selection.target.windows() {
        render_powershell(selection, installer)
    } else {
        render_posix(selection, installer)
    }
}

pub fn invitation_is_unexpired(expires_at: i64, now_unix: i64) -> bool {
    expires_at > now_unix
}

fn validate_installer_contract(source: &str, target: Target) -> Result<(), BootstrapError> {
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

fn render_powershell(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
    let digest = ps_quote(&installer.sha256);
    let url = ps_quote(installer.url.as_str());
    let args = [
        ("HubUrl", selection.hub_url.as_str()),
        ("Name", selection.name.as_str()),
        ("SshUser", selection.ssh_user.as_str()),
        ("AgentUri", selection.agent_url.as_str()),
        ("AgentSha256", selection.agent_sha256.as_str()),
        ("ArchiveUri", selection.archive_url.as_str()),
        ("ArchiveSha256", selection.archive_sha256.as_str()),
        ("AgentVersion", selection.version.as_str()),
        ("Target", selection.target.as_str()),
    ]
    .into_iter()
    .map(|(name, value)| format!(" -{name} {}", ps_quote(value)))
    .collect::<String>();
    let script = format!(
        "$ErrorActionPreference='Stop'; $tls=[Enum]::ToObject([Net.SecurityProtocolType],3072); [Net.ServicePointManager]::SecurityProtocol=$tls; $u=New-Object Uri({url}); if($u.Scheme -cne 'https'){{throw 'HTTPS required'}}; $r=[Net.HttpWebRequest]::Create($u); $r.AllowAutoRedirect=$false; $r.Timeout=30000; $r.ReadWriteTimeout=30000; $v=$r.GetResponse(); try{{if([int]$v.StatusCode -ne 200 -or $v.ContentLength -gt 1048576){{throw 'Pinned installer response rejected'}}; $s=$v.GetResponseStream(); $m=New-Object IO.MemoryStream; $b=New-Object byte[] 65536; while(($n=$s.Read($b,0,$b.Length)) -gt 0){{if($m.Length+$n -gt 1048576){{throw 'Installer too large'}}; $m.Write($b,0,$n)}}; $bytes=$m.ToArray()}}finally{{$v.Close()}}; $h=New-Object Security.Cryptography.SHA256Managed; try{{$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}}finally{{$h.Clear()}}; if($actual -cne {digest}){{throw 'Installer SHA-256 mismatch'}}; $script=[Text.Encoding]::UTF8.GetString($bytes); & ([scriptblock]::Create($script)){args}\n",
        args = args
    );
    let utf16le = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, utf16le)
    )
}

fn render_posix(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
    let mut args = [
        ("--hub-url", selection.hub_url.as_str()),
        ("--name", selection.name.as_str()),
        ("--ssh-user", selection.ssh_user.as_str()),
        ("--agent-url", selection.agent_url.as_str()),
        ("--agent-sha256", selection.agent_sha256.as_str()),
        ("--archive-url", selection.archive_url.as_str()),
        ("--archive-sha256", selection.archive_sha256.as_str()),
        ("--agent-version", selection.version.as_str()),
        ("--target", selection.target.as_str()),
    ]
    .into_iter()
    .map(|(name, value)| format!(" {} {}", sh_quote(name), sh_quote(value)))
    .collect::<String>();
    if let Some(path) = &selection.bootstrap_hub_ca_cert {
        args.push_str(&format!(
            " {} {}",
            sh_quote("--hub-ca-cert"),
            sh_quote(&path.to_string_lossy())
        ));
    }
    let curl_ca = selection
        .bootstrap_hub_ca_cert
        .as_ref()
        .map(|path| format!("--cacert {} ", sh_quote(&path.to_string_lossy())))
        .unwrap_or_default();
    format!(
        "set -eu\ninstaller=$(mktemp)\ntrap 'rm -f \"$installer\"' EXIT HUP INT TERM\ncurl {curl_ca}--fail --silent --show-error --proto '=https' --tlsv1.2 --max-filesize 1048576 --connect-timeout 10 --max-time 30 -o \"$installer\" {}\nprintf '%s  %s\\n' {} \"$installer\" | sha256sum -c -\n/bin/sh \"$installer\"{}\n",
        sh_quote(installer.url.as_str()),
        sh_quote(&installer.sha256),
        args,
        curl_ca = curl_ca
    )
}

fn validate_https_url(value: &Url) -> Result<(), BootstrapError> {
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

fn validate_path(path: &str) -> Result<(), BootstrapError> {
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

fn https_url(value: &str) -> Result<Url, BootstrapError> {
    let url = Url::parse(value).map_err(|_| BootstrapError::Invalid("malformed HTTPS URL"))?;
    validate_https_url(&url)?;
    Ok(url)
}

fn origin(url: &Url) -> (String, String, Option<u16>) {
    (
        url.scheme().to_owned(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port(),
    )
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn semver(value: &str) -> bool {
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

fn canonical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn has_version_segment(segments: &[&str], version: &str) -> bool {
    segments
        .iter()
        .any(|segment| *segment == version || *segment == format!("v{version}"))
}

fn ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn installer_preflight_rejects_unsafe_ca_path_without_network_access() {
        let root = tempfile::tempdir().expect("private CA fixture");
        let huge = root.path().join("oversized-ca.pem");
        std::fs::write(&huge, vec![b'A'; 64 * 1024 + 1]).expect("oversized fixture");
        let selected = selection(Target::LinuxX64);
        let error = verify_installer(&selected, Some(&huge))
            .await
            .expect_err("oversized trust anchor must be rejected before HTTPS");
        assert!(error.to_string().contains("unsafe or invalid"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = root.path().join("linked-ca.pem");
            symlink(&huge, &linked).expect("create hostile CA symlink");
            assert!(
                verify_installer(&selected, Some(&linked)).await.is_err(),
                "HTTPS trust root symlinks must not be followed"
            );
        }
    }

    fn selection(target: Target) -> ArtifactSelection {
        let agent = if target.windows() {
            "hostlink-agent.exe"
        } else {
            "hostlink-agent"
        };
        ArtifactSelection {
            installer_url: Url::parse("https://artifacts.example/install.sh?immutable=1").unwrap(),
            installer_sha256: "a".repeat(64),
            agent_url: Url::parse(&format!(
                "https://artifacts.example/v1.2.3/{}/{agent}",
                target.as_str()
            ))
            .unwrap(),
            agent_sha256: "b".repeat(64),
            archive_url: Url::parse(&format!(
                "https://artifacts.example/v1.2.3/hostlink-agent-{}.zip",
                target.as_str()
            ))
            .unwrap(),
            archive_sha256: "c".repeat(64),
            version: "1.2.3".into(),
            target,
            name: "lab-host".into(),
            ssh_user: "hostlink".into(),
            hub_url: "https://hub.example".into(),
            bootstrap_hub_ca_cert: None,
        }
    }

    #[test]
    fn supports_only_the_four_installer_targets_and_matching_archive_names() {
        for target in [
            Target::Win7X86,
            Target::Win7X64,
            Target::Win11X64,
            Target::LinuxX64,
        ] {
            assert!(selection(target).validate().is_ok());
        }
        assert!(Target::parse("x86_64-unknown-linux-musl").is_err());
        let mut wrong = selection(Target::Win7X86);
        wrong.archive_url = Url::parse(
            "https://artifacts.example/v9.9.9/hostlink-agent-x86_64-win7-windows-msvc.zip",
        )
        .unwrap();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn rejects_missing_or_swapped_source_pins_and_unsafe_urls_before_request() {
        let mut missing = selection(Target::LinuxX64);
        missing.installer_sha256.clear();
        assert!(missing.validate().is_err());
        let mut swapped = selection(Target::LinuxX64);
        swapped.archive_url =
            Url::parse("https://other.example/v1.2.3/hostlink-agent-x86_64-unknown-linux-gnu.zip")
                .unwrap();
        assert!(swapped.validate().is_err());
        assert!(https_url("https://[malformed").is_err());
        for url in [
            "http://artifacts.example/i.sh",
            "https://user@artifacts.example/i.sh",
            "https://@artifacts.example/i.sh",
            "https://artifacts.example/i.sh#frag",
            "https://artifacts.example/a/%2e%2e/i.sh",
            "https://artifacts.example/a/%2f../i.sh",
            "https://artifacts.example/a/%252e%252e/i.sh",
        ] {
            assert!(parse_artifact_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn renders_powershell_and_posix_commands_with_quoted_arguments_and_no_token() {
        let mut windows = selection(Target::Win7X64);
        windows.installer_url = Url::parse("https://artifacts.example/i'$(whoami).ps1").unwrap();
        let command = render_command(
            &windows,
            &VerifiedInstaller {
                url: windows.installer_url.clone(),
                sha256: windows.installer_sha256.clone(),
            },
        );
        assert!(
            command.starts_with("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ")
        );
        let encoded = command.split_whitespace().last().unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
        let (pairs, remainder) = decoded.as_chunks::<2>();
        assert!(remainder.is_empty());
        let words = pairs
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        let script = String::from_utf16(&words).unwrap();
        assert!(script.contains("New-Object Uri('https://artifacts.example/i''$(whoami).ps1')"));
        assert!(script.contains("-Name 'lab-host'"));
        assert!(script.contains("$r.AllowAutoRedirect=$false"));
        assert!(script.contains(&windows.installer_sha256));
        assert!(!command.contains("invite-token"));

        let mut linux = selection(Target::LinuxX64);
        linux.installer_url =
            Url::parse("https://artifacts.example/i'$(touch%20/tmp/pwned).sh").unwrap();
        linux.bootstrap_hub_ca_cert = Some("/private/fixture ca.pem".into());
        let command = render_command(
            &linux,
            &VerifiedInstaller {
                url: linux.installer_url.clone(),
                sha256: linux.installer_sha256.clone(),
            },
        );
        assert!(command.contains("'--name' 'lab-host'"));
        assert!(command.contains("'https://artifacts.example/i'\\''$(touch%20/tmp/pwned).sh'"));
        assert!(command.contains("--cacert '/private/fixture ca.pem'"));
        assert!(command.contains("'--hub-ca-cert' '/private/fixture ca.pem'"));
        assert!(command.contains("sha256sum -c -"));
        assert!(!command.contains("token"));
    }

    #[test]
    fn installer_contract_is_platform_specific_and_version_is_exact_semver() {
        assert!(semver("1.2.3-rc.1+build.4"));
        assert!(!semver("1.2.3-"));
        assert!(!semver("01.2.3"));
        assert!(!semver("latest"));
        assert!(validate_installer_contract("HubUrl Name SshUser AgentUri AgentSha256 ArchiveUri ArchiveSha256 AgentVersion Target Read-Host -AsSecureString", Target::Win11X64).is_ok());
        assert!(validate_installer_contract("--hub-url --name --ssh-user --agent-url --agent-sha256 --archive-url --archive-sha256 --agent-version --target stty -echo", Target::LinuxX64).is_ok());
        assert!(validate_installer_contract("--hub-url --name", Target::LinuxX64).is_err());
        assert!(
            validate_installer_contract(
                include_str!("../../agent/assets/Install-HostLink-Agent.ps1"),
                Target::Win7X86
            )
            .is_ok()
        );
        assert!(
            validate_installer_contract(
                include_str!("../../agent/assets/install-hostlink-agent.sh"),
                Target::LinuxX64
            )
            .is_ok()
        );
        let source = "--hub-url --name --ssh-user --agent-url --agent-sha256 --archive-url --archive-sha256 --agent-version --target stty -echo";
        let source_sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
        assert!(
            validate_installer_bytes(source.as_bytes(), &source_sha256, Target::LinuxX64).is_ok()
        );
        assert!(
            validate_installer_bytes(source.as_bytes(), &"0".repeat(64), Target::LinuxX64).is_err()
        );
        assert!(invitation_is_unexpired(101, 100));
        assert!(!invitation_is_unexpired(100, 100));
        assert!(!invitation_is_unexpired(99, 100));
    }

    #[tokio::test]
    async fn local_disposable_http_fixture_rejects_redirects_and_accepts_exact_bytes() {
        async fn serve(response: &'static str) -> Option<String> {
            let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!("SKIP local HTTP fixture: sandbox denied loopback bind: {error}");
                    return None;
                }
                Err(error) => panic!("bind disposable HTTP fixture: {error}"),
            };
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
                tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                    .await
                    .unwrap();
            });
            Some(format!("http://{address}/installer"))
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let valid = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest";
        let Some(valid_url) = serve(valid).await else {
            return;
        };
        let bytes = fetch_bytes(&client, Url::parse(&valid_url).unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"test");
        let redirect = "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/script\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let Some(redirect_url) = serve(redirect).await else {
            return;
        };
        let error = fetch_bytes(&client, Url::parse(&redirect_url).unwrap())
            .await
            .unwrap_err();
        assert!(error.contains("without redirects"));
    }
}
