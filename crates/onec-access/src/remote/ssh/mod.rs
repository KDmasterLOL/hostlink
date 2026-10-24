//! Controller-owned SSH transport. GatewayControl and TargetSsh retain separate trust identities.

mod channel;
mod connect;
mod phase;
#[cfg(test)]
mod tests;
mod trust;

pub(in crate::remote) use channel::EmbeddedSshChannel as RemoteChannel;
pub(crate) use phase::ApprovedRoutesFailure;
pub use phase::SshPhaseFailure;

const MANAGED_AGENT_CONTROL_PORT: u16 = 27391;
const SSH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const GATEWAY_ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const SSH_SESSION_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
