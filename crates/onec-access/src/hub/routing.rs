//! Hub-backed managed-host route selection and concrete remote-server resolution.

use super::*;
use crate::{RemoteServer, sync_hub_ssh_hosts};

/// Chooses target-SSH when the hub projection is ready, otherwise the gateway-control route.
pub async fn hub_runtime_server(
    hub: &HubClient,
    agent: &HubAgent,
    ssh_ready: bool,
) -> AppResult<(RemoteServer, &'static str)> {
    if ssh_ready {
        Ok((hub.ssh_control_server(agent).await?, "hub-target-ssh"))
    } else {
        Ok((
            hub.gateway_control_server(agent).await?,
            "hub-gateway-control",
        ))
    }
}

/// Resolves a configured managed host to its current remote-control route.
pub async fn resolve_remote_server(name: &str) -> AppResult<RemoteServer> {
    let config_path = hub_config_path()?;
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "onec-access config {}; configure access before using remote operations",
            config_path.display()
        ))
    })?;
    let agent = hub
        .resolve_agent(name)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {name:?}")))?;
    resolve_agent_route(&hub, &agent).await
}

impl HubClient {
    /// Resolves a remote-control route by this hub's exact stable machine identity.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when the machine identity is absent/ambiguous or the route
    /// cannot be established from this hub's current inventory.
    pub async fn resolve_remote_server_for_machine(
        &self,
        machine_id: &str,
    ) -> AppResult<RemoteServer> {
        let agent = self
            .resolve_agent(machine_id)
            .await?
            .filter(|agent| agent.machine_id.eq_ignore_ascii_case(machine_id))
            .ok_or_else(|| {
                crate::not_found_error(format!("hub machine identity {machine_id:?}"))
            })?;
        resolve_agent_route(self, &agent).await
    }
}

async fn resolve_agent_route(hub: &HubClient, agent: &HubAgent) -> AppResult<RemoteServer> {
    let ssh = sync_hub_ssh_hosts(hub, false).await?;
    let ssh_ready = ssh
        .configured_hosts
        .iter()
        .any(|host| host.eq_ignore_ascii_case(&agent.name));
    hub_runtime_server(hub, agent, ssh_ready)
        .await
        .map(|(server, _)| server)
}
