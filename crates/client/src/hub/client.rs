//! Bounded HTTPS client for HostLink Hub management operations.

use std::{fs::OpenOptions, io::Read, path::Path, time::Duration};

use hostlink_hub::{
    DisplayNameRequest, GatewayEndpoint, HostsResponse, HubInfo, InviteRequest, InviteResponse,
    RegisteredHost, RevokeReceipt,
};
use private_fs::PrivateDir;
use reqwest::{Method, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    config::{
        HubClientError, HubConfig, MAX_BODY_BYTES, MAX_CONFIG_BYTES, parse_origin,
        read_private_credential, select_host,
    },
    routes::validate_gateway_list,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Authenticated bounded Hub v2 client. Construction performs no network I/O.
pub struct HubClient {
    pub(super) base: Url,
    pub(super) token: SecretString,
    pub(super) client: reqwest::Client,
}

impl HubClient {
    /// Reads only the HostLink-managed private controller configuration without loading the
    /// operator credential, CA, SSH keys, or constructing a network client.
    ///
    /// # Errors
    /// Returns [`HubClientError::Credential`] if the containing private directory
    /// or file is unsafe/inaccessible, or the bounded JSON does not match [`HubConfig`].
    pub fn read_config(path: &Path) -> Result<HubConfig, HubClientError> {
        let parent = path.parent().ok_or(HubClientError::Credential)?;
        let name = path.file_name().ok_or(HubClientError::Credential)?;
        let directory = PrivateDir::open(parent).map_err(|_| HubClientError::Credential)?;
        let file = directory
            .open_file(name)
            .map_err(|_| HubClientError::Credential)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| HubClientError::Credential)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(HubClientError::Credential);
        }
        serde_json::from_slice(&bytes).map_err(|_| HubClientError::Credential)
    }

    /// Parse a private config and construct its usable HTTP client once.
    pub fn from_file(path: &Path) -> Result<(Self, HubConfig), HubClientError> {
        let config = Self::read_config(path)?;
        let client = Self::from_config(&config)?;
        Ok((client, config))
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
        Ok(self.get_json::<HostsResponse>("/v2/hosts").await?.hosts)
    }

    /// Resolves only an exact canonical invitation name. Display labels and IDs
    /// cannot accidentally authorize adoption; an absent name means fresh install.
    ///
    /// # Errors
    /// Returns inventory errors or rejects an ambiguous/noncanonical selector.
    pub async fn invitation_identity(
        &self,
        name: &str,
    ) -> Result<Option<RegisteredHost>, HubClientError> {
        super::config::select_invitation_identity(&self.list_hosts().await?, name)
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
        let info: HubInfo = self.get_json("/v2/info").await?;
        info.validate().map_err(|_| HubClientError::Response)?;
        let gateways = info.gateways;
        validate_gateway_list(&gateways)?;
        Ok(gateways)
    }

    /// Creates a bounded one-use enrollment invitation. The caller controls the explicit token display boundary.
    pub async fn invite(
        &self,
        name: Option<String>,
        ttl_seconds: u64,
    ) -> Result<InviteResponse, HubClientError> {
        self.invite_with_repair(name, ttl_seconds, None).await
    }

    /// Issues a repair invite bound to an exact inventory identity, or a fresh invite.
    /// The Hub rechecks name/ID and captures the keys atomically at issuance.
    ///
    /// # Errors
    /// Returns an authorization, identity conflict or transport error from the Hub.
    pub async fn invite_with_repair(
        &self,
        name: Option<String>,
        ttl_seconds: u64,
        repair_machine_id: Option<hostlink_hub::MachineId>,
    ) -> Result<InviteResponse, HubClientError> {
        self.request_json(
            Method::POST,
            "/v2/invites",
            Some(&InviteRequest {
                repair_machine_id,
                ttl_seconds,
                name,
                rotate_machine_id: None,
            }),
        )
        .await
    }

    /// Issues an explicit operator-authorized key replacement for this exact host.
    ///
    /// # Errors
    /// Returns Hub authorization/identity conflicts or transport errors.
    pub async fn invite_replacement(
        &self,
        host: &hostlink_hub::RegisteredHost,
        ttl_seconds: u64,
    ) -> Result<InviteResponse, HubClientError> {
        self.request_json(
            Method::POST,
            "/v2/invites",
            Some(&InviteRequest {
                ttl_seconds,
                name: Some(host.name.clone()),
                repair_machine_id: None,
                rotate_machine_id: Some(host.machine_id.clone()),
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
        self.request_json(
            Method::PATCH,
            &format!("/v2/hosts/{}/display-name", host.machine_id),
            Some(&DisplayNameRequest {
                display_name: display_name.into(),
            }),
        )
        .await
    }

    /// Revokes new managed access and requires an explicit truthful reconciliation receipt.
    pub async fn revoke(&self, host: &RegisteredHost) -> Result<RevokeReceipt, HubClientError> {
        let receipt: RevokeReceipt = self
            .request_json(
                Method::DELETE,
                &format!("/v2/hosts/{}", host.machine_id),
                None::<&()>,
            )
            .await?;
        if !receipt.revoked_new_connections
            || receipt.confirmed_session_terminated
            || receipt.remote_uninstall
            || receipt.authorized_key_projection != "reconciled"
        {
            return Err(HubClientError::Response);
        }
        Ok(receipt)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, HubClientError> {
        self.request_json(Method::GET, path, None::<&()>).await
    }

    pub(super) async fn request_json<T: for<'de> Deserialize<'de>, B: Serialize + ?Sized>(
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
