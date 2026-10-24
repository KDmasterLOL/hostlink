//! HostLink managed-machine controller library.
//!
//! This crate owns the hub HTTP client, controller-local configuration, managed SSH projection,
//! authenticated agent RPC, persistent jobs, file transfer and TCP forwarding. It deliberately
//! contains no hub persistence/server implementation and no 1C project/domain policy.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod error;
mod host;
mod http_body;
mod hub;
mod paths;
mod remote;
mod ssh_argv;
mod tool;

use std::path::Path;

pub use error::{AppError, AppResult, ProcessError};
pub(crate) use error::{
    http_error, io_error, json_error, private_path_error, process_start_error, protocol_error,
    remote_transport_error,
};
#[doc(hidden)]
pub use error::{invalid_config, not_found_error, process_failed_error};
pub use host::{
    SshHostSkip, SshHostSyncReport, managed_gateway_known_hosts_path, managed_ssh_config_path,
    managed_target_known_hosts_path, resolve_managed_ssh_agent, run_managed_ssh,
    sync_hub_ssh_hosts, user_ssh_config_path,
};
pub use hostlink_hub::HubHttpsUrl;
pub use hub::{
    ControllerGateway, HubAgent, HubClient, HubControllerConfig, HubInvite, ManagedTargetEffect,
    hub_config_path, hub_runtime_server, resolve_remote_server,
};
pub use remote::{
    GatewayRoute, GatewayTrust, RemoteAgentClient, RemoteCarrier, RemoteProbeResult,
    RemoteRunLocalPaths, RemoteServer, RemoteTcpStream, SshPhaseFailure,
};
pub use ssh_argv::encode_remote_command;
pub use tool::{ResolvedTool, resolve_ssh_tool};

pub(crate) use paths::config_path;

pub(crate) fn sha256_file(path: &Path) -> AppResult<String> {
    hostlink_core::sha256_file(path).map_err(|source| io_error(path, source))
}
