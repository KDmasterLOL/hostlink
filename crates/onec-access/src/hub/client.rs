//! Async authenticated HTTP client and hub-to-remote-server projection.

use super::*;
use crate::http_body::{
    HUB_CONTROL_JSON_MAX_BYTES, HUB_ERROR_BODY_MAX_BYTES, bounded_error_text,
    read_bounded_response_json,
};
use crate::{GatewayRoute, GatewayTrust};
use tokio::sync::OnceCell;

#[derive(Debug, Clone)]
/// Async authenticated client for the controller-side onec-hub API.
pub struct HubClient {
    pub(super) config: HubControllerConfig,
    pub(super) token: SecretString,
    pub(super) http: Client,
    pub(super) info: std::sync::Arc<OnceCell<HubInfoResponse>>,
}

impl HubClient {
    /// Creates a client from validated controller configuration and resolves the operator token.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when config/token validation or HTTP client construction fails.
    pub fn from_config(config: HubControllerConfig) -> AppResult<Self> {
        config.validate()?;
        let token = config.token()?;
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| {
                crate::http_error(format!("failed to create onec-hub client: {error}"))
            })?;
        Ok(Self {
            config,
            token,
            http,
            info: std::sync::Arc::new(OnceCell::new()),
        })
    }

    /// Creates a client from the default configuration when that configuration exists.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when an existing configuration or token cannot be loaded.
    pub fn configured() -> AppResult<Option<Self>> {
        HubControllerConfig::load_optional()?
            .map(Self::from_config)
            .transpose()
    }

    /// Returns the validated controller configuration bound to this client.
    pub fn config(&self) -> &HubControllerConfig {
        &self.config
    }

    /// Fetches the hub's public HTTPS URL projection.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for request/status/body-limit/JSON or URL-policy failures.
    pub async fn public_url(&self) -> AppResult<HubHttpsUrl> {
        Ok(self.hub_info().await?.public_url)
    }

    async fn hub_info(&self) -> AppResult<HubInfoResponse> {
        self.info
            .get_or_try_init(|| async {
                let response = self
                    .http
                    .get(self.endpoint(["v1", "info"])?)
                    .bearer_auth(self.token.expose_secret())
                    .send()
                    .await
                    .map_err(|error| crate::http_error(format!("onec-hub info failed: {error}")))?;
                let response = require_success(response, "hub info").await?;
                let info = read_bounded_response_json::<HubInfoResponse>(
                    response,
                    HUB_CONTROL_JSON_MAX_BYTES,
                    "onec-hub info response",
                )
                .await?;
                Ok(info)
            })
            .await
            .cloned()
    }

    async fn effective_gateways(&self) -> AppResult<Vec<GatewayRoute>> {
        let info = self.hub_info().await?;
        let routes = if info.gateways.is_empty() {
            let known_hosts = self.config.known_hosts.clone().ok_or_else(|| {
                crate::invalid_config(
                    "legacy hub gateway fallback requires configured known_hosts".to_owned(),
                )
            })?;
            self.config
                .gateways
                .iter()
                .map(|gateway| GatewayRoute {
                    host: gateway.host.clone(),
                    user: gateway.user.clone(),
                    port: gateway.port,
                    trust: GatewayTrust::KnownHosts(known_hosts.clone()),
                })
                .collect::<Vec<_>>()
        } else {
            info.gateways
                .into_iter()
                .map(|gateway| {
                    gateway.validate_fields().map_err(|error| {
                        crate::invalid_config(format!("invalid hub gateway topology: {error}"))
                    })?;
                    Ok(GatewayRoute {
                        host: gateway.host,
                        user: gateway.user,
                        port: gateway.port,
                        trust: GatewayTrust::PinnedPublicKey(gateway.host_public_key),
                    })
                })
                .collect::<AppResult<Vec<_>>>()?
        };
        let mut seen = std::collections::HashSet::new();
        for route in &routes {
            route.validate()?;
            if !seen.insert((route.host.to_ascii_lowercase(), route.port)) {
                return Err(crate::invalid_config(
                    "hub gateway topology contains duplicate host/port endpoints".to_owned(),
                ));
            }
        }
        if routes.is_empty() {
            return Err(crate::invalid_config(
                "hub gateway topology and local fallback are both empty".to_owned(),
            ));
        }
        Ok(routes)
    }

    pub(crate) async fn gateway_routes(&self) -> AppResult<Vec<GatewayRoute>> {
        self.effective_gateways().await
    }

    /// Lists enrolled agents visible to the authenticated operator.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for request/status/body-limit or JSON failures.
    pub async fn list_agents(&self) -> AppResult<Vec<HubAgent>> {
        let response = self
            .http
            .get(self.endpoint(["v1", "agents"])?)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            .map_err(|error| crate::http_error(format!("onec-hub list agents failed: {error}")))?;
        let response = require_success(response, "list agents").await?;
        read_bounded_response_json::<AgentsResponse>(
            response,
            HUB_CONTROL_JSON_MAX_BYTES,
            "onec-hub agents response",
        )
        .await
        .map(|value| value.agents)
    }

    /// Creates one short-lived one-use enrollment invite.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for request/status/body-limit or response-decoding failures.
    pub async fn create_invite(
        &self,
        name: Option<&str>,
        ttl_seconds: u64,
    ) -> AppResult<HubInvite> {
        let response = self
            .http
            .post(self.endpoint(["v1", "invites"])?)
            .bearer_auth(self.token.expose_secret())
            .json(&InviteRequest { ttl_seconds, name })
            .send()
            .await
            .map_err(|error| {
                crate::http_error(format!("onec-hub create invite failed: {error}"))
            })?;
        let response = require_success(response, "create invite").await?;
        read_bounded_response_json::<HubInvite>(
            response,
            HUB_CONTROL_JSON_MAX_BYTES,
            "onec-hub invite response",
        )
        .await
    }

    /// Resolves one agent by exact name/machine-id/id, then unique machine-id/id prefix.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for an empty or ambiguous selector, or when listing agents fails.
    pub async fn resolve_agent(&self, requested: &str) -> AppResult<Option<HubAgent>> {
        let requested = requested.trim();
        if requested.is_empty() {
            return Err(crate::invalid_config(
                "remote server selector must not be empty".to_owned(),
            ));
        }
        let agents = self.list_agents().await?;
        let exact = agents
            .iter()
            .filter(|agent| {
                agent.name.eq_ignore_ascii_case(requested)
                    || agent.machine_id.eq_ignore_ascii_case(requested)
                    || agent.id.eq_ignore_ascii_case(requested)
            })
            .cloned()
            .collect::<Vec<_>>();
        match exact.as_slice() {
            [agent] => return Ok(Some(agent.clone())),
            [] => {}
            _ => {
                return Err(crate::invalid_config(format!(
                    "onec-hub selector {requested:?} is ambiguous"
                )));
            }
        }
        let prefixes = agents
            .iter()
            .filter(|agent| {
                agent.machine_id.starts_with(requested) || agent.id.starts_with(requested)
            })
            .cloned()
            .collect::<Vec<_>>();
        match prefixes.as_slice() {
            [] => Ok(None),
            [agent] => Ok(Some(agent.clone())),
            _ => Err(crate::invalid_config(format!(
                "onec-hub selector prefix {requested:?} is ambiguous"
            ))),
        }
    }

    /// Updates the optional display-only label for one exact enrolled machine.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, authorization, or identity mismatches.
    pub async fn set_display_name(
        &self,
        agent: &HubAgent,
        display_name: Option<&str>,
    ) -> AppResult<Option<String>> {
        let response = self
            .http
            .patch(self.endpoint(["v1", "agents", agent.machine_id.as_str(), "display-name"])?)
            .bearer_auth(self.token.expose_secret())
            .json(&serde_json::json!({"display_name": display_name}))
            .send()
            .await
            .map_err(|error| {
                crate::http_error(format!("onec-hub display name update failed: {error}"))
            })?;
        let response = require_success(response, "set display name").await?;
        let receipt = read_bounded_response_json::<super::model::DisplayNameResponse>(
            response,
            HUB_CONTROL_JSON_MAX_BYTES,
            "onec-hub display name update",
        )
        .await?;
        if receipt.machine_id != agent.machine_id || receipt.name != agent.name {
            return Err(crate::invalid_config(
                "hub display name update returned wrong machine identity".to_owned(),
            ));
        }
        if receipt.display_name.as_deref() != display_name.map(str::trim) {
            return Err(crate::invalid_config(
                "hub display name update returned a different label; inspect current inventory"
                    .to_owned(),
            ));
        }
        Ok(receipt.display_name)
    }

    /// Removes one enrolled machine by its stable machine identity.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for endpoint construction, request, or non-success status failures.
    pub async fn remove_agent(&self, agent: &HubAgent) -> AppResult<()> {
        let response = self
            .http
            .delete(self.endpoint(["v1", "agents", agent.machine_id.as_str()])?)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            .map_err(|error| crate::http_error(format!("onec-hub remove agent failed: {error}")))?;
        require_success(response, "remove agent").await?;
        Ok(())
    }

    async fn control_credential(&self, agent: &HubAgent) -> AppResult<SecretString> {
        if let Some(secret) = agent.legacy_control_secret.as_ref() {
            return Ok(secret.clone());
        }
        let response = self
            .http
            .get(self.endpoint([
                "v1",
                "agents",
                agent.machine_id.as_str(),
                "control-credential",
            ])?)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            .map_err(|error| {
                crate::http_error(format!(
                    "onec-hub control credential retrieval failed: {error}"
                ))
            })?;
        let response = require_success(response, "get agent control credential").await?;
        let credential = read_bounded_response_json::<ControlCredentialResponse>(
            response,
            HUB_CONTROL_JSON_MAX_BYTES,
            "onec-hub control credential response",
        )
        .await?;
        validate_control_credential_response(agent, credential)
    }

    /// Projects one enrolled agent into a gateway-control [`RemoteServer`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the resulting remote-server trust/transport model is invalid.
    pub async fn gateway_control_server(&self, agent: &HubAgent) -> AppResult<RemoteServer> {
        let secret = self.control_credential(agent).await?;
        self.gateway_control_server_with_secret(agent, secret).await
    }

    /// Projects migration-approved carriers from one identity-checked control credential.
    ///
    /// Target SSH is optional when enrollment has no usable target username; the gateway route is
    /// required. Other projection errors are returned so malformed routes or identities cannot be
    /// hidden by falling back to another carrier. Resolving both routes this way avoids a second
    /// hub credential request for migration fallback.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the authenticated credential identity is invalid or a
    /// required gateway/available SSH route cannot be safely projected.
    pub async fn migration_control_servers(
        &self,
        agent: &HubAgent,
    ) -> AppResult<(Option<RemoteServer>, RemoteServer)> {
        let secret = self.control_credential(agent).await?;
        let ssh = if agent
            .username
            .as_deref()
            .is_some_and(|username| !username.trim().is_empty())
        {
            Some(
                self.ssh_control_server_with_secret(agent, secret.clone())
                    .await?,
            )
        } else {
            None
        };
        let gateway = self
            .gateway_control_server_with_secret(agent, secret)
            .await?;
        Ok((ssh, gateway))
    }

    pub(super) async fn gateway_control_server_with_secret(
        &self,
        agent: &HubAgent,
        secret: SecretString,
    ) -> AppResult<RemoteServer> {
        self.remote_server_with_secret(agent, secret, RemoteCarrier::GatewayControl)
            .await
    }

    async fn remote_server_with_secret(
        &self,
        agent: &HubAgent,
        secret: SecretString,
        carrier: RemoteCarrier,
    ) -> AppResult<RemoteServer> {
        let gateways = self.effective_gateways().await?;
        let (target_user, target_known_hosts, target_host_key_alias) =
            if carrier == RemoteCarrier::TargetSsh {
                (
                    agent.username.clone(),
                    Some(crate::managed_target_known_hosts_path()?),
                    Some(crate::host::managed_target_host_key_alias(agent)),
                )
            } else {
                (None, None, None)
            };
        let server = RemoteServer {
            name: agent.name.clone(),
            gateways,
            remote_port: agent.remote_port,
            carrier,
            persistence_mode: agent.persistence_mode.clone(),
            identity: self.config.identity.clone(),
            known_hosts: self.config.known_hosts.clone(),
            target_user,
            target_known_hosts,
            target_host_key_alias,
            secret,
        };
        server.validate()?;
        Ok(server)
    }

    /// Projects one enrolled agent into an embedded target-SSH [`RemoteServer`].
    ///
    /// Target trust is pinned through the generated managed target known_hosts file and host-key
    /// alias rather than ambient OpenSSH configuration.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the resulting SSH/trust model is incomplete or invalid.
    pub async fn ssh_control_server(&self, agent: &HubAgent) -> AppResult<RemoteServer> {
        let secret = self.control_credential(agent).await?;
        self.ssh_control_server_with_secret(agent, secret).await
    }

    pub(super) async fn ssh_control_server_with_secret(
        &self,
        agent: &HubAgent,
        secret: SecretString,
    ) -> AppResult<RemoteServer> {
        self.remote_server_with_secret(agent, secret, RemoteCarrier::TargetSsh)
            .await
    }

    fn endpoint<'a>(&self, segments: impl IntoIterator<Item = &'a str>) -> AppResult<reqwest::Url> {
        Ok(self.config.url.append_segments(segments)?.as_url().clone())
    }
}

fn validate_control_credential_response(
    agent: &HubAgent,
    credential: ControlCredentialResponse,
) -> AppResult<SecretString> {
    if credential.machine_id != agent.machine_id {
        return Err(crate::invalid_config(format!(
            "onec-hub control credential identity mismatch: expected {:?}, got {:?}",
            agent.machine_id, credential.machine_id
        )));
    }
    if credential.control_credential_nonce != agent.control_credential_nonce {
        return Err(crate::invalid_config(format!(
            "onec-hub control credential generation changed for {:?}; refresh managed inventory and retry",
            agent.machine_id
        )));
    }
    Ok(credential.control_secret)
}

async fn require_success(
    response: reqwest::Response,
    operation: &str,
) -> AppResult<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = bounded_error_text(response, HUB_ERROR_BODY_MAX_BYTES).await;
    Err(crate::http_error(format!(
        "onec-hub {operation} returned HTTP {}{}",
        status.as_u16(),
        if body.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", body.trim())
        }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_agent() -> HubAgent {
        HubAgent {
            id: "agent-id".into(),
            machine_id: "machine-id".into(),
            name: "server-a".into(),
            display_name: None,
            hostname: "SERVER-A".into(),
            username: Some("TIS".into()),
            os: "windows".into(),
            arch: "x86_64".into(),
            agent_version: "0.1.0".into(),
            transport: "open_ssh".into(),
            persistence_mode: Some("user-session".into()),
            remote_port: 41001,
            control_credential_nonce: Some("aa".repeat(32)),
            legacy_control_secret: None,
            ssh_public_key: "ssh-ed25519 fixture".into(),
            ssh_host_public_key: Some("ssh-ed25519 host-fixture".into()),
            enrolled_at: 1,
            updated_at: 2,
        }
    }

    #[tokio::test]
    async fn legacy_bulk_control_secret_is_consumed_without_per_agent_endpoint() {
        let config = HubControllerConfig::new(
            "https://hub.example.test",
            "gateway.example.test",
            "operator",
        )
        .expect("config");
        let client = HubClient {
            config,
            token: "x".repeat(32).into(),
            http: Client::new(),
            info: std::sync::Arc::new(OnceCell::new()),
        };
        let mut agent = fixture_agent();
        agent.control_credential_nonce = None;
        agent.legacy_control_secret = Some("legacy-secret".repeat(4).into());

        let secret = client
            .control_credential(&agent)
            .await
            .expect("legacy compatibility secret");

        assert_eq!(
            secret.expose_secret(),
            agent
                .legacy_control_secret
                .as_ref()
                .expect("legacy secret")
                .expose_secret()
        );
    }

    #[test]
    fn per_agent_control_credential_requires_same_identity_and_generation() {
        let agent = fixture_agent();
        let accepted = validate_control_credential_response(
            &agent,
            ControlCredentialResponse {
                machine_id: agent.machine_id.clone(),
                control_credential_nonce: agent.control_credential_nonce.clone(),
                control_secret: "current-secret".repeat(4).into(),
            },
        )
        .expect("matching credential");
        assert_eq!(accepted.expose_secret(), "current-secret".repeat(4));

        let identity_error = validate_control_credential_response(
            &agent,
            ControlCredentialResponse {
                machine_id: "other-machine".into(),
                control_credential_nonce: agent.control_credential_nonce.clone(),
                control_secret: "other-secret".repeat(4).into(),
            },
        )
        .expect_err("identity mismatch");
        assert!(identity_error.to_string().contains("identity mismatch"));

        let generation_error = validate_control_credential_response(
            &agent,
            ControlCredentialResponse {
                machine_id: agent.machine_id.clone(),
                control_credential_nonce: Some("bb".repeat(32)),
                control_secret: "rotated-secret".repeat(4).into(),
            },
        )
        .expect_err("generation mismatch");
        assert!(generation_error.to_string().contains("generation changed"));
    }

    #[test]
    fn endpoint_preserves_base_prefix_and_encodes_dynamic_segments() {
        let config = HubControllerConfig::new(
            "https://hub.example.test/root/",
            "gateway.example.test",
            "operator",
        )
        .expect("config");
        let client = HubClient {
            config,
            token: "x".repeat(32).into(),
            http: Client::new(),
            info: std::sync::Arc::new(OnceCell::new()),
        };

        let endpoint = client
            .endpoint(["v1", "agents", "machine/id"])
            .expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://hub.example.test/root/v1/agents/machine%2Fid"
        );
    }
}
