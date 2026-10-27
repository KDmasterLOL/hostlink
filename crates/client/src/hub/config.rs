//! Hub configuration, response-independent errors, and private local inputs.

use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use hostlink_hub::RegisteredHost;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(super) const MAX_BODY_BYTES: usize = 64 * 1024;
pub(super) const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

/// Controller-local settings needed to turn authoritative Hub records into pinned SSH targets.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// HTTPS origin of the Hub, without a path, query, or credentials.
    pub hub_url: String,
    /// Optional additional PEM CA for a privately operated Hub TLS endpoint.
    #[serde(default)]
    pub hub_ca_cert: Option<PathBuf>,
    /// Owner-only file containing the operator bearer token.
    pub token_file: PathBuf,
    /// Explicit SSH account accepted by the Agent; never inferred from host metadata.
    pub ssh_user: String,
    /// Owner-only Ed25519 controller identity.
    pub identity: PathBuf,
    /// Owner-only Ed25519 identity used for the approved gateway.
    pub gateway_identity: PathBuf,
    /// Explicit primary Hub route as `host:port`; required when Hub lists multiple gateways.
    #[serde(default)]
    pub preferred_gateway: Option<String>,
}

/// Safe errors from the Hub client. HTTP bodies and credential values are never rendered.
#[derive(Debug, Error)]
pub enum HubClientError {
    /// Hub configuration or host metadata is invalid.
    #[error("invalid Hub configuration or registry record: {0}")]
    Invalid(String),
    /// No host matched the supplied canonical name or machine ID.
    #[error("Hub host was not found")]
    NotFound,
    /// More than one host matched a short selector.
    #[error("Hub host selector is ambiguous; use a canonical name or full machine ID")]
    Ambiguous,
    /// Hub rejected the operator credential.
    #[error("Hub authorization failed")]
    Unauthorized,
    /// Hub returned a non-success response; status only is included.
    #[error("Hub request failed with HTTP status {0}")]
    HttpStatus(StatusCode),
    /// Hub request failed or exceeded its deadline.
    #[error("Hub request failed or timed out")]
    Request,
    /// Hub response exceeded the fixed size bound or did not match v2.
    #[error("Hub response is oversized or invalid")]
    Response,
    /// Local credential files are unsafe or inaccessible.
    #[error("Hub credential file is unsafe or inaccessible")]
    Credential,
    /// DNS lookup did not produce exactly one approved route address in time.
    #[error("gateway DNS lookup failed, timed out, or returned multiple addresses")]
    GatewayDns,
}

pub(super) fn parse_origin(value: &str) -> Result<Url, HubClientError> {
    if value.len() > 2048 {
        return Err(HubClientError::Invalid("Hub URL is too long".into()));
    }
    let url = Url::parse(value)
        .map_err(|_| HubClientError::Invalid("Hub URL must be an HTTPS origin".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HubClientError::Invalid(
            "Hub URL must be an HTTPS origin without credentials, path, query, or fragment".into(),
        ));
    }
    Ok(url)
}

pub(super) fn select_host(
    hosts: &[RegisteredHost],
    selector: &str,
) -> Result<RegisteredHost, HubClientError> {
    let exact: Vec<_> = hosts
        .iter()
        .filter(|host| host.name == selector || host.machine_id.as_str() == selector)
        .collect();
    match exact.as_slice() {
        [host] => return Ok((*host).clone()),
        [] => {}
        _ => return Err(HubClientError::Ambiguous),
    }
    let prefix: Vec<_> = hosts
        .iter()
        .filter(|host| host.machine_id.as_str().starts_with(selector))
        .collect();
    match prefix.as_slice() {
        [host] => Ok((*host).clone()),
        [] => Err(HubClientError::NotFound),
        _ => Err(HubClientError::Ambiguous),
    }
}

pub(super) fn read_private_credential(path: &Path) -> Result<String, HubClientError> {
    let before = fs::symlink_metadata(path).map_err(|_| HubClientError::Credential)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path).map_err(|_| HubClientError::Credential)?;
    let metadata = file.metadata().map_err(|_| HubClientError::Credential)?;
    if !metadata.is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or memory-safety preconditions.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(HubClientError::Credential);
        }
    }
    #[cfg(windows)]
    crate::connect::validate_private_file(&file).map_err(|_| HubClientError::Credential)?;
    #[cfg(not(any(unix, windows)))]
    return Err(HubClientError::Credential);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HubClientError::Credential)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(HubClientError::Credential);
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|_| HubClientError::Credential)
}
