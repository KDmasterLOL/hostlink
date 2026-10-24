//! Redacted hub agent/invite models and private HTTP payload DTOs.

use super::*;

#[derive(Debug, Clone, Deserialize)]
/// Controller projection of one enrolled hub agent.
pub struct HubAgent {
    /// Hub record identifier.
    pub id: String,
    /// Stable machine identity used for enrollment/removal.
    pub machine_id: String,
    /// Human-readable enrolled agent name.
    pub name: String,
    /// Optional Unicode label; not an authentication/SSH/managed-selector identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Target operating-system hostname.
    pub hostname: String,
    /// Optional target login user advertised for SSH access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Target operating-system identifier.
    pub os: String,
    /// Target CPU architecture identifier.
    pub arch: String,
    /// Running resident-agent version.
    pub agent_version: String,
    /// Enrolled transport mode reported by the hub.
    pub transport: String,
    /// Optional persisted resident-agent mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    /// Gateway loopback reverse-forward port assigned to this agent.
    pub remote_port: u16,
    /// Non-secret credential generation projected by current hubs.
    #[serde(default)]
    pub(crate) control_credential_nonce: Option<String>,
    /// Transitional secret returned only by pre-1C-173 hub servers.
    #[serde(default, rename = "control_secret")]
    pub(crate) legacy_control_secret: Option<SecretString>,
    /// Enrolled target SSH public key.
    pub ssh_public_key: String,
    /// Optional pinned target SSH host public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_host_public_key: Option<String>,
    /// Enrollment timestamp supplied by the hub.
    pub enrolled_at: i64,
    /// Last-update timestamp supplied by the hub.
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct DisplayNameResponse {
    pub(super) machine_id: String,
    pub(super) name: String,
    pub(super) display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AgentsResponse {
    pub(super) agents: Vec<HubAgent>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ControlCredentialResponse {
    pub(super) machine_id: String,
    #[serde(default)]
    pub(super) control_credential_nonce: Option<String>,
    pub(super) control_secret: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct HubInfoResponse {
    pub(super) public_url: HubHttpsUrl,
    #[serde(default)]
    pub(super) gateways: Vec<hostlink_hub::GatewayEndpoint>,
}

#[derive(Debug, Serialize)]
pub(super) struct InviteRequest<'a> {
    pub(super) ttl_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
/// One-use enrollment invite returned by the hub.
pub struct HubInvite {
    token: SecretString,
    /// Expiration timestamp supplied by the hub.
    pub expires_at: i64,
    /// Public HTTPS hub URL embedded in bootstrap material.
    pub public_url: HubHttpsUrl,
}

impl HubInvite {
    /// Expose the one-use enrollment token only at an explicit bootstrap boundary.
    pub fn token(&self) -> &str {
        self.token.expose_secret()
    }
}
