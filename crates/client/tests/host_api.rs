//! Compile-level contract for a downstream user of the managed Host API.
//!
//! This test does not contact the Hub or an Agent. Functional authorization,
//! route selection and SSH semantics are covered by focused Hub and E2E tests.

use hostlink::{
    connect::HostConnection,
    host::{Host, HostError, PendingHost},
    hub::{HubClient, HubConfig},
};
use hostlink_hub::{InviteResponse, MachineId};

async fn managed_caller(hub: &HubClient, config: &HubConfig) -> Result<(), HostError> {
    // Invitation is a pending enrollment, never an authenticated Host.
    let pending: PendingHost = Host::create(hub, Some("lab-win7".into()), 900).await?;
    let requested: Option<&str> = pending.requested_name();
    assert_eq!(requested, Some("lab-win7"));
    let _invitation: InviteResponse = pending.into_invitation();

    // A new connection obtains fresh Hub identity/routes, not a saved HostSpec.
    let (host, mut ssh): (Host, HostConnection) = Host::connect(hub, config, "lab-win7").await?;
    let _: &MachineId = host.machine_id();
    let _: &str = host.name();
    let _output = ssh.exec("hostname", &[]).await?;
    ssh.close().await?;
    Ok(())
}

#[test]
fn managed_host_public_contract_is_available_to_downstream_callers() {
    // Referencing the async function ensures the body is type checked without
    // contacting external services or inventing a fake enrolled machine.
    let _ = managed_caller;
}
