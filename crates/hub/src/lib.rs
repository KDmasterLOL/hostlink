//! Shared, secret-conscious HostLink fleet-management wire types.
//! The server runtime is optional so clients can depend on this crate without Axum.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MachineId(String);

impl MachineId {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
            || value.starts_with(['-', '.'])
            || value.ends_with(['-', '.'])
        {
            return Err("machine_id must be 1-128 canonical lowercase ASCII characters".into());
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for MachineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for MachineId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
impl<'de> Deserialize<'de> for MachineId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayEndpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub host_public_key: String,
}

impl GatewayEndpoint {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0
            || self.user.is_empty()
            || self.user.len() > 128
            || self.user.chars().any(char::is_whitespace)
        {
            return Err("invalid gateway endpoint fields".into());
        }
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.chars().any(char::is_whitespace)
            || self.host.contains('/')
        {
            return Err("invalid gateway host".into());
        }
        validate_ed25519_public_key(&self.host_public_key)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredHost {
    pub machine_id: MachineId,
    pub name: String,
    pub display_name: Option<String>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
    pub ssh_public_key: String,
    pub ssh_host_public_key: String,
    pub remote_port: u16,
    pub enrolled_at: i64,
    pub updated_at: i64,
}

/// Response envelope for the authoritative Hub v2 host inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostsResponse {
    /// Registered hosts returned by the Hub.
    pub hosts: Vec<RegisteredHost>,
}

/// Hub v2 management capabilities and approved gateway routes.
///
/// Unknown fields are intentionally accepted for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubInfo {
    /// Hub management API version; currently must be 2.
    pub api_version: u8,
    /// Whether managed fleet operations are available.
    pub management: bool,
    /// Operator-approved SSH gateway routes.
    pub gateways: Vec<GatewayEndpoint>,
    /// Execution transport; currently must be `russh`.
    pub execution_transport: String,
    /// Host inventory endpoint; currently must be `/v2/hosts`.
    pub hosts_endpoint: String,
}

impl HubInfo {
    /// Checks that this response advertises the supported Hub v2 contract.
    pub fn validate(&self) -> Result<(), String> {
        if self.api_version != 2
            || !self.management
            || self.execution_transport != "russh"
            || self.hosts_endpoint != "/v2/hosts"
        {
            return Err("unsupported Hub management capabilities".into());
        }
        Ok(())
    }
}

/// Receipt returned after the Hub commits a host revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeReceipt {
    /// Whether authorization for new connections was revoked.
    pub revoked_new_connections: bool,
    /// Whether termination of existing sessions was confirmed.
    pub confirmed_session_terminated: bool,
    /// Whether the remote Agent was uninstalled.
    pub remote_uninstall: bool,
    /// Result of reconciling the gateway authorized-key projection.
    pub authorized_key_projection: String,
}

/// Request body for changing a host's display-only label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayNameRequest {
    /// New display label.
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    #[serde(default = "default_invite_ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub name: Option<String>,
    /// Supplying a machine ID creates an explicit, operator-approved key rotation invite.
    #[serde(default)]
    pub rotate_machine_id: Option<MachineId>,
    /// Identity-preserving repair, requiring proof of the registered reverse key.
    /// Mutually exclusive with key rotation; a fresh invite cannot repair a host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_machine_id: Option<MachineId>,
}
fn default_invite_ttl() -> u64 {
    900
}

#[derive(Debug, Clone)]
pub struct InviteResponse {
    pub token: SecretString,
    pub expires_at: i64,
}
impl Serialize for InviteResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("InviteResponse", 2)?;
        state.serialize_field("token", self.token.expose_secret())?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.end()
    }
}
impl<'de> Deserialize<'de> for InviteResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            token: String,
            expires_at: i64,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.token.len() != 64
            || !wire
                .token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(serde::de::Error::custom(
                "invalid invitation token encoding",
            ));
        }
        Ok(Self {
            token: SecretString::from(wire.token),
            expires_at: wire.expires_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub token: SecretString,
    pub machine_id: MachineId,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
    pub ssh_public_key: String,
    pub ssh_host_public_key: String,
    /// OpenSSH signature over [`Self::repair_message`] by the existing reverse key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_signature: Option<String>,
}

/// Domain separator for identity-preserving repair signatures.
pub const REPAIR_NAMESPACE: &str = "hostlink-repair-v1";

impl EnrollRequest {
    /// Canonical, length-prefixed transcript binding proof to this one-use token,
    /// identity, both keys and all submitted inventory fields. Never log these bytes.
    pub fn repair_message(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for field in [
            REPAIR_NAMESPACE,
            self.token.expose_secret(),
            self.machine_id.as_str(),
            &self.name,
            &self.hostname,
            &self.os,
            &self.arch,
            &self.agent_version,
            &self.ssh_public_key,
            &self.ssh_host_public_key,
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    }
}
fn serialize_secret<S: serde::Serializer>(
    value: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.expose_secret())
}
fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    pub host: RegisteredHost,
    pub gateways: Vec<GatewayEndpoint>,
    pub operator_ssh_public_keys: Vec<String>,
}

pub fn validate_ed25519_public_key(value: &str) -> Result<(), String> {
    let key: ssh_key::PublicKey = value
        .parse()
        .map_err(|_| "invalid SSH public key".to_string())?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("SSH key must use Ed25519".into());
    }
    Ok(())
}

pub fn canonical_ed25519_public_key(value: &str) -> Result<String, String> {
    let key: ssh_key::PublicKey = value
        .parse()
        .map_err(|_| "invalid SSH public key".to_string())?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("SSH key must use Ed25519".into());
    }
    ssh_key::PublicKey::new(key.key_data().clone(), "")
        .to_openssh()
        .map_err(|_| "SSH public key cannot be serialized".to_string())
}

#[cfg(feature = "server")]
mod enrollment;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
mod ssh_authorization;
#[cfg(feature = "server")]
mod state;
#[cfg(feature = "server")]
pub use server::{HubConfig, HubError, HubService, router};
