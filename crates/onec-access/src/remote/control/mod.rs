//! Remote-agent control RPC grouped by authority.

mod discovery;
mod execution;
mod filesystem;
mod lifecycle;
mod request;

#[cfg(test)]
pub(in crate::remote) use filesystem::RunLocalPrepareTimingEvent;
pub(crate) use filesystem::{sftp_carrier_unavailable_error, sftp_not_offered_error};
