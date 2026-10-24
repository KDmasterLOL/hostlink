//! Remote agent transport façade.
//!
//! Public server/client types stay flat while control RPC, file transfer, TCP forwarding,
//! SSH lifecycle and protocol framing have separate owners.

mod control;
mod forwarding;
mod model;
mod protocol;
mod ssh;
#[cfg(test)]
mod tests;
mod transfer;

pub(crate) use control::{sftp_carrier_unavailable_error, sftp_not_offered_error};
pub(in crate::remote) use transfer::{SFTP_IO_STAGE_DEADLINE, UploadStage, sftp_stage};

pub use ssh::SshPhaseFailure;

pub use model::{
    GatewayRoute, GatewayTrust, RemoteAgentClient, RemoteCarrier, RemoteProbeResult,
    RemoteRunLocalPaths, RemoteServer, RemoteTcpStream,
};

/// Internal distinction needed to keep an old agent's opaque application failure separate from
/// transport, malformed-protocol, and typed remote errors during run-local cache admission.
pub(crate) enum PathSha256Probe {
    Present(u64, String),
    Missing,
    OpaqueFailure(crate::AppError),
}

pub(crate) async fn select_managed_ssh_gateway(
    gateways: &[GatewayRoute],
    identity: &std::path::Path,
    reverse_port: u16,
) -> crate::AppResult<usize> {
    // Preserve the remote-transport boundary for controller callers. The internal SSH module
    // no longer adds a second, policy-free forwarding hop to the embedded channel owner.
    ssh::RemoteChannel::select_gateway_route(gateways, identity, reverse_port).await
}

#[cfg(test)]
use protocol::read_response_unbuffered;
#[cfg(all(test, unix))]
use transfer::FILE_TRANSFER_SHA256_CAPABILITY;
