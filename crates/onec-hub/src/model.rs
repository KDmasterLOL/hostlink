//! HTTP request/response DTOs and shared application state.

use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct InviteRequest {
    #[serde(default = "default_invite_ttl")]
    pub(super) ttl_seconds: u64,
    #[serde(default)]
    pub(super) name: Option<String>,
}
fn default_invite_ttl() -> u64 {
    900
}

#[derive(Serialize)]
pub(super) struct InviteResponse {
    #[serde(serialize_with = "serialize_secret")]
    pub(super) token: SecretString,
    pub(super) expires_at: i64,
    pub(super) public_url: HubHttpsUrl,
}

#[derive(Debug, Deserialize)]
pub(super) struct EnrollRequest {
    pub(super) machine_id: String,
    pub(super) name: String,
    pub(super) hostname: String,
    #[serde(default)]
    pub(super) username: Option<String>,
    pub(super) os: String,
    pub(super) arch: String,
    pub(super) agent_version: String,
    pub(super) transport: String,
    #[serde(default)]
    pub(super) persistence_mode: Option<String>,
    pub(super) ssh_public_key: String,
    #[serde(default)]
    pub(super) ssh_host_public_key: Option<String>,
}

#[derive(Serialize)]
pub(super) struct EnrollResponse {
    pub(super) id: String,
    pub(super) machine_id: String,
    pub(super) name: String,
    pub(super) remote_port: u16,
    #[serde(serialize_with = "serialize_secret")]
    pub(super) control_secret: SecretString,
    pub(super) gateways: Vec<hostlink_hub::GatewayEndpoint>,
    /// Legacy first-gateway host retained for older installers during migration.
    pub(super) gateway_host: String,
    /// Legacy first-gateway SSH port retained for older installers during migration.
    pub(super) gateway_ssh_port: u16,
    /// Legacy first-gateway SSH user retained for older installers during migration.
    pub(super) agent_ssh_user: String,
    /// Legacy first-gateway host key retained for older installers during migration.
    pub(super) gateway_host_public_key: String,
    pub(super) operator_ssh_public_key: String,
    pub(super) operator_ssh_public_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateDisplayNameRequest {
    pub(super) display_name: serde_json::Value,
}

#[derive(Serialize)]
pub(super) struct AgentView<'a> {
    #[serde(flatten)]
    pub(super) record: &'a AgentRecord,
}

#[derive(Debug, Deserialize)]
pub(super) struct SshAuthorizedKeyLookupRequest {
    pub(super) key_type: String,
    pub(super) key_blob: String,
}

#[derive(Serialize)]
pub(super) struct AgentsResponse<'a> {
    pub(super) agents: Vec<AgentView<'a>>,
}

#[derive(Serialize)]
pub(super) struct ControlCredentialResponse {
    pub(super) machine_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) control_credential_nonce: Option<String>,
    #[serde(serialize_with = "serialize_secret")]
    pub(super) control_secret: SecretString,
}

pub(super) struct App {
    pub(super) config: HubConfig,
    pub(super) operator_token: SecretString,
    pub(super) agent_secret_key: SecretString,
    pub(super) ssh_lookup_token: Option<SecretString>,
    pub(super) state_writer: Mutex<()>,
}

fn serialize_secret<S>(value: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.expose_secret())
}
