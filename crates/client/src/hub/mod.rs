//! HTTPS management client for the authoritative HostLink Hub v2 registry.

use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use hostlink_hub::{GatewayEndpoint, InviteRequest, InviteResponse, RegisteredHost};
use reqwest::{Method, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{GatewayHop, GatewayRoute, HostSpec};

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Confirmed result of Hub revocation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevokeReceipt {
    /// Hub revoked authorization for new connections.
    pub revoked_new_connections: bool,
    /// Hub cannot confirm termination of already established SSH sessions.
    pub confirmed_session_terminated: bool,
    /// Hub does not uninstall the remote Agent.
    pub remote_uninstall: bool,
    /// Gateway authorized key projection result.
    pub authorized_key_projection: String,
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

/// Authenticated bounded Hub v2 client. Construction performs no network I/O.
pub struct HubClient {
    base: Url,
    token: SecretString,
    client: reqwest::Client,
}

impl HubClient {
    /// Reads a bounded owner-only controller config file and validates its token source.
    pub fn read_config(path: &Path) -> Result<HubConfig, HubClientError> {
        let value = read_private_credential(path)?;
        let config: HubConfig =
            serde_json::from_str(&value).map_err(|_| HubClientError::Credential)?;
        // Constructor validation is deliberately local-only; callers may choose when to connect.
        let _ = Self::from_config(&config)?;
        Ok(config)
    }

    /// Loads the owner-only token and creates a strict HTTPS client without proxies or redirects.
    pub fn from_config(config: &HubConfig) -> Result<Self, HubClientError> {
        Self::from_config_with_ca(config, config.hub_ca_cert.as_deref())
    }

    /// Loads the normal HTTPS client with an additional explicitly supplied CA certificate.
    /// The system/web PKI roots remain enabled; this never disables certificate validation.
    pub fn from_config_with_ca(
        config: &HubConfig,
        ca_certificate: Option<&Path>,
    ) -> Result<Self, HubClientError> {
        let base = parse_origin(&config.hub_url)?;
        if config.ssh_user.is_empty()
            || config.ssh_user.len() > 128
            || config.ssh_user.chars().any(char::is_whitespace)
        {
            return Err(HubClientError::Invalid("SSH user is invalid".into()));
        }
        let token = read_private_credential(&config.token_file)?;
        if token.is_empty() || token.len() > 4096 || token.contains(['\r', '\n']) {
            return Err(HubClientError::Credential);
        }
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT);
        if let Some(path) = ca_certificate {
            builder = builder.add_root_certificate(read_ca_certificate(path)?);
        }
        let client = builder.build().map_err(|_| HubClientError::Request)?;
        Ok(Self {
            base,
            token: SecretString::from(token),
            client,
        })
    }

    /// Returns one authoritative inventory snapshot without probing any Agent.
    pub async fn list_hosts(&self) -> Result<Vec<RegisteredHost>, HubClientError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            hosts: Vec<RegisteredHost>,
        }
        Ok(self.get_json::<Response>("/v2/hosts").await?.hosts)
    }

    /// Selects an exact canonical name/full ID or a unique machine-ID prefix.
    pub async fn resolve_host(&self, selector: &str) -> Result<RegisteredHost, HubClientError> {
        let selector = selector.trim();
        if selector.is_empty() || selector.len() > 128 {
            return Err(HubClientError::Invalid("host selector is invalid".into()));
        }
        let hosts = self.list_hosts().await?;
        select_host(&hosts, selector)
    }

    /// Reads and validates Hub v2 management capabilities and its approved gateway routes.
    pub async fn info(&self) -> Result<Vec<GatewayEndpoint>, HubClientError> {
        let value: serde_json::Value = self.get_json("/v2/info").await?;
        if value.get("api_version").and_then(|v| v.as_u64()) != Some(2)
            || value.get("management").and_then(|v| v.as_bool()) != Some(true)
            || value.get("execution_transport").and_then(|v| v.as_str()) != Some("russh")
            || value.get("hosts_endpoint").and_then(|v| v.as_str()) != Some("/v2/hosts")
        {
            return Err(HubClientError::Response);
        }
        let gateways: Vec<GatewayEndpoint> = serde_json::from_value(
            value
                .get("gateways")
                .cloned()
                .ok_or(HubClientError::Response)?,
        )
        .map_err(|_| HubClientError::Response)?;
        for gateway in &gateways {
            gateway.validate().map_err(HubClientError::Invalid)?;
        }
        validate_gateway_list(&gateways)?;
        Ok(gateways)
    }

    /// Creates a bounded one-use enrollment invitation. The caller controls the explicit token display boundary.
    pub async fn invite(
        &self,
        name: Option<String>,
        ttl_seconds: u64,
    ) -> Result<InviteResponse, HubClientError> {
        self.request_json(
            Method::POST,
            "/v2/invites",
            Some(&InviteRequest {
                ttl_seconds,
                name,
                rotate_machine_id: None,
            }),
        )
        .await
    }

    /// Sets a display-only label on a registered host.
    pub async fn set_display_name(
        &self,
        host: &RegisteredHost,
        display_name: &str,
    ) -> Result<RegisteredHost, HubClientError> {
        #[derive(Serialize)]
        struct Body<'a> {
            display_name: &'a str,
        }
        self.request_json(
            Method::PATCH,
            &format!("/v2/hosts/{}/display-name", host.machine_id),
            Some(&Body { display_name }),
        )
        .await
    }

    /// Revokes new managed access and requires an explicit truthful reconciliation receipt.
    pub async fn revoke(&self, host: &RegisteredHost) -> Result<RevokeReceipt, HubClientError> {
        let receipt: RevokeReceipt = self
            .request_json::<serde_json::Value, ()>(
                Method::DELETE,
                &format!("/v2/hosts/{}", host.machine_id),
                None,
            )
            .await
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| HubClientError::Response)
            })?;
        if !receipt.revoked_new_connections
            || receipt.confirmed_session_terminated
            || receipt.remote_uninstall
            || receipt.authorized_key_projection != "reconciled"
        {
            return Err(HubClientError::Response);
        }
        Ok(receipt)
    }

    /// Resolves a fresh authoritative host and its explicitly selected approved routes.
    pub async fn resolve_host_spec(
        &self,
        selector: &str,
        config: &HubConfig,
    ) -> Result<HostSpec, HubClientError> {
        let host = self.resolve_host(selector).await?;
        let gateways = self.info().await?;
        host_spec_from_approved_routes(host, &gateways, config).await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, HubClientError> {
        self.request_json(Method::GET, path, None::<&()>).await
    }

    async fn request_json<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, HubClientError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| HubClientError::Invalid("invalid Hub endpoint".into()))?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(self.token.expose_secret());
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| HubClientError::Request)?;
        let status = response.status();
        if !status.is_success() {
            return Err(
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    HubClientError::Unauthorized
                } else {
                    HubClientError::HttpStatus(status)
                },
            );
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BODY_BYTES as u64)
        {
            return Err(HubClientError::Response);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| HubClientError::Request)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(HubClientError::Response);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| HubClientError::Response)
    }
}

pub(crate) fn read_ca_certificate(path: &Path) -> Result<reqwest::Certificate, HubClientError> {
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
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err(HubClientError::Credential);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HubClientError::Credential)?;
    if bytes.len() > 64 * 1024 {
        return Err(HubClientError::Credential);
    }
    reqwest::Certificate::from_pem(&bytes).map_err(|_| HubClientError::Credential)
}

fn parse_origin(value: &str) -> Result<Url, HubClientError> {
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

fn select_host(hosts: &[RegisteredHost], selector: &str) -> Result<RegisteredHost, HubClientError> {
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

fn read_private_credential(path: &Path) -> Result<String, HubClientError> {
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

fn validate_pin(value: &str) -> Result<(), HubClientError> {
    let key: russh::keys::PublicKey = value
        .parse()
        .map_err(|_| HubClientError::Invalid("Hub supplied an invalid SSH host key".into()))?;
    if key.algorithm().to_string() != "ssh-ed25519" {
        return Err(HubClientError::Invalid(
            "Hub SSH host key must be Ed25519".into(),
        ));
    }
    Ok(())
}

/// Resolves the host's exact gateway pins from one authoritative Hub inventory.
///
/// Only a trusted configured gateway is a valid primary when the Hub advertises
/// multiple routes. The remaining Hub-approved routes are retained solely for
/// transient initial-connection failures, never for key/authentication failures.
pub async fn host_spec_from_approved_routes(
    host: RegisteredHost,
    gateways: &[GatewayEndpoint],
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    validate_gateway_list(gateways)?;
    let primary_index = match (gateways, config.preferred_gateway.as_deref()) {
        ([_], None) => 0,
        ([], _) => {
            return Err(HubClientError::Invalid(
                "Hub has no approved gateway".into(),
            ));
        }
        (_, selected) => select_primary_gateway(gateways, selected)?,
    };
    // A healthy explicitly selected gateway must not become unusable merely
    // because an optional Hub-approved alternate is temporarily missing in DNS.
    // Resolve alternates concurrently so many offline edges do not multiply
    // the controller's discovery deadline. All pins were validated above.
    let mut addresses = vec![None; gateways.len()];
    addresses[primary_index] = Some(resolve_gateway(&gateways[primary_index]).await?);
    let mut optional = tokio::task::JoinSet::new();
    for (index, gateway) in gateways.iter().enumerate() {
        if index != primary_index {
            let gateway = gateway.clone();
            optional.spawn(async move { (index, resolve_gateway(&gateway).await) });
        }
    }
    while let Some(result) = optional.join_next().await {
        let (index, address) = result.map_err(|_| HubClientError::GatewayDns)?;
        if let Ok(address) = address {
            addresses[index] = Some(address);
        }
    }

    let primary_address = addresses[primary_index].expect("selected primary was resolved");
    let mut routes = Vec::with_capacity(gateways.len());
    routes.push((&gateways[primary_index], primary_address));
    let mut resolved = std::collections::BTreeSet::new();
    resolved.insert((primary_address, gateways[primary_index].user.as_str()));
    for (index, (gateway, address)) in gateways.iter().zip(addresses).enumerate() {
        if index == primary_index {
            continue;
        }
        if let Some(address) = address {
            if !resolved.insert((address, gateway.user.as_str())) {
                return Err(HubClientError::Invalid(
                    "Hub routes resolve to duplicate gateway endpoints".into(),
                ));
            }
            routes.push((gateway, address));
        }
    }
    host_spec_from_routes(host, &routes, 0, config)
}

/// Resolves one registry record and an already-selected approved route into the existing SSH type.
pub async fn host_spec_from(
    host: RegisteredHost,
    gateway: &GatewayEndpoint,
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    let address = resolve_gateway(gateway).await?;
    host_spec_from_routes(host, &[(gateway, address)], 0, config)
}

fn host_spec_from_routes(
    host: RegisteredHost,
    routes: &[(&GatewayEndpoint, SocketAddr)],
    primary_index: usize,
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    let (gateway, address) = routes.get(primary_index).ok_or(HubClientError::Response)?;
    validate_pin(&host.ssh_host_public_key)?;
    let mut alternates = Vec::with_capacity(routes.len().saturating_sub(1));
    for (index, (endpoint, address)) in routes.iter().enumerate() {
        validate_pin(&endpoint.host_public_key)?;
        if index != primary_index {
            alternates.push(GatewayRoute {
                address: *address,
                user: endpoint.user.clone(),
                identity: config.gateway_identity.clone(),
                host_public_key: endpoint.host_public_key.clone(),
            });
        }
    }
    Ok(HostSpec {
        endpoint: SocketAddr::from(([127, 0, 0, 1], host.remote_port)),
        user: config.ssh_user.clone(),
        identity: config.identity.clone(),
        host_public_key: host.ssh_host_public_key,
        gateway: Some(GatewayHop {
            address: *address,
            user: gateway.user.clone(),
            identity: config.gateway_identity.clone(),
            host_public_key: gateway.host_public_key.clone(),
            reverse_port: host.remote_port,
            alternates,
        }),
    })
}

fn validate_gateway_list(gateways: &[GatewayEndpoint]) -> Result<(), HubClientError> {
    if gateways.len() > 16 {
        return Err(HubClientError::Invalid(
            "Hub lists more than 16 approved gateways".into(),
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut pins = std::collections::BTreeSet::new();
    for gateway in gateways {
        gateway.validate().map_err(HubClientError::Invalid)?;
        if gateway.user.is_empty()
            || gateway.user.len() > 64
            || !gateway
                .user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(HubClientError::Invalid(
                "Hub gateway SSH user is invalid for the Client".into(),
            ));
        }
        let identity = (
            gateway.host.to_ascii_lowercase(),
            gateway.port,
            gateway.user.as_str(),
        );
        if !identities.insert(identity) {
            return Err(HubClientError::Invalid(
                "Hub lists a duplicate gateway identity".into(),
            ));
        }
        if !pins.insert(gateway.host_public_key.as_str()) {
            return Err(HubClientError::Invalid(
                "Hub lists a duplicate gateway host key pin".into(),
            ));
        }
        validate_pin(&gateway.host_public_key)?;
    }
    Ok(())
}

fn select_primary_gateway(
    gateways: &[GatewayEndpoint],
    preferred: Option<&str>,
) -> Result<usize, HubClientError> {
    let Some(preferred) = preferred else {
        return Err(HubClientError::Invalid(
            "Hub lists multiple gateways; set preferred_gateway to an exact host:port from /v2/info".into(),
        ));
    };
    let matches: Vec<_> = gateways
        .iter()
        .enumerate()
        .filter(|(_, gateway)| format!("{}:{}", gateway.host, gateway.port) == preferred)
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(HubClientError::Invalid(
            "preferred_gateway does not match exactly one Hub-approved host:port".into(),
        )),
    }
}

async fn resolve_gateway(gateway: &GatewayEndpoint) -> Result<SocketAddr, HubClientError> {
    let mut addresses = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((gateway.host.as_str(), gateway.port)),
    )
    .await
    .map_err(|_| HubClientError::GatewayDns)?
    .map_err(|_| HubClientError::GatewayDns)?;
    let first = addresses.next().ok_or(HubClientError::GatewayDns)?;
    if addresses.next().is_some() {
        return Err(HubClientError::GatewayDns);
    }
    Ok(first)
}

#[cfg(test)]
mod tests;
