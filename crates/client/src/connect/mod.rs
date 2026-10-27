//! Pinned russh connection, with optional authenticated gateway hop.

mod gateway;
mod identity;
mod session;

#[cfg(windows)]
pub(crate) use identity::validate_private_file;
pub use session::{HostConnection, SshClientError};
pub(crate) use session::{MAX_TRANSFER_BYTES, OPERATION_TIMEOUT};
#[cfg(test)]
pub(crate) use session::{PinHandler, connect_stream_authenticated};

#[cfg(test)]
use identity::{MAX_IDENTITY_BYTES, load_identity};
#[cfg(test)]
use russh::keys;
#[cfg(test)]
use std::fs;

#[cfg(test)]
mod tests;
