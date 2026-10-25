//! Pure-Rust SSH controller: pinned russh transport and direct/forwarded execution.

pub mod connect;
pub mod exec;
pub mod forward;
pub mod run;
pub mod sftp;

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Pinned SSH target identity. Constructing a HostSpec never performs I/O.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub endpoint: SocketAddr,
    pub user: String,
    pub identity: PathBuf,
    pub host_public_key: String,
    pub gateway: Option<GatewayHop>,
}

/// An explicitly approved gateway that exposes a loopback reverse TCP port.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayHop {
    pub address: SocketAddr,
    pub user: String,
    pub identity: PathBuf,
    pub host_public_key: String,
    pub reverse_port: u16,
}
