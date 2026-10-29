//! Embedded russh transport: authenticated exec, SFTP and direct-tcpip.

mod config;
mod server;

pub(crate) use config::prepare;
pub(crate) use server::serve_prepared_until;

// Retain the old public entrypoints for external callers; Agent lifecycle
// supervision itself is owned by runtime, not the SSH protocol module.
pub use crate::runtime::{serve, serve_on};
