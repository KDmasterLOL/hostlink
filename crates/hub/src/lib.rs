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
