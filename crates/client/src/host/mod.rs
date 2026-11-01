//! Managed host identity and explicit invitation/connection transitions.

use std::time::{Duration, SystemTime};

use hostlink_hub::{InviteResponse, MachineId};
use thiserror::Error;

use crate::{
    connect::{HostConnection, SshClientError},
    hub::{HubClient, HubClientError, HubConfig, host_spec_from_approved_routes},
};

/// Canonical registered identity resolved by the Hub after successful SSH authentication.
/// This is an identity snapshot, not a guarantee of continued enrollment or availability.
#[derive(Debug)]
pub struct Host {
    machine_id: MachineId,
    name: String,
}

/// One-use enrollment invitation; it does not represent an enrolled or running Agent.
/// Debug output relies on the shared invitation type's secret redaction.
#[derive(Debug)]
pub struct PendingHost {
    requested_name: Option<String>,
    invitation: InviteResponse,
}

/// Managed lifecycle errors, preserving the existing Hub and SSH error owners.
#[derive(Debug, Error)]
pub enum HostError {
    /// Authoritative lookup, invitation, or approved route resolution failed.
    #[error("managed host Hub operation failed: {0}")]
    Hub(#[from] HubClientError),
    /// Pinned SSH connection or authentication failed.
    #[error("managed host SSH connection failed: {0}")]
    Ssh(#[from] SshClientError),
    /// The returned invitation has already expired according to system UTC.
    #[error("Hub invitation has expired")]
    ExpiredInvitation,
}

impl Host {
    /// Stable machine identity from the authoritative registry.
    pub fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    /// Canonical registry name, independent of display labels and selectors.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Explicitly requests one invitation, without registering or starting an Agent.
    ///
    /// # Errors
    /// Returns the Hub error if invitation creation fails, or
    /// [`HostError::ExpiredInvitation`] if the response is already expired.
    pub async fn create(
        hub: &HubClient,
        name: Option<String>,
        ttl_seconds: u64,
    ) -> Result<PendingHost, HostError> {
        let invitation = hub.invite(name.clone(), ttl_seconds).await?;
        PendingHost::from_invitation(name, invitation)
    }

    /// Resolves fresh Hub identity and approved routes, then authenticates pinned russh SSH.
    /// Returns the existing transport only after successful authentication.
    ///
    /// # Errors
    /// Returns Hub lookup/route errors or the pinned SSH connection error.
    /// No cached identity or route is used when authoritative resolution fails.
    pub async fn connect(
        hub: &HubClient,
        config: &HubConfig,
        selector: &str,
    ) -> Result<(Self, HostConnection), HostError> {
        let registered = hub.resolve_host(selector).await?;
        let gateways = hub.info().await?;
        let machine_id = registered.machine_id.clone();
        let name = registered.name.clone();
        let spec = host_spec_from_approved_routes(registered, &gateways, config).await?;
        let connection = HostConnection::connect(&spec).await?;
        Ok((Self { machine_id, name }, connection))
    }
}

impl PendingHost {
    fn from_invitation(
        requested_name: Option<String>,
        invitation: InviteResponse,
    ) -> Result<Self, HostError> {
        let expires_at = u64::try_from(invitation.expires_at)
            .ok()
            .and_then(|seconds| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)));
        if expires_at.is_none_or(|expires_at| expires_at <= SystemTime::now()) {
            return Err(HostError::ExpiredInvitation);
        }
        Ok(Self {
            requested_name,
            invitation,
        })
    }

    /// Optional requested name; no registered machine identity exists yet.
    pub fn requested_name(&self) -> Option<&str> {
        self.requested_name.as_deref()
    }

    /// Consumes the pending state at the caller's explicit secret handoff boundary.
    pub fn into_invitation(self) -> InviteResponse {
        self.invitation
    }
}

#[cfg(test)]
mod tests;
