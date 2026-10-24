//! Managed OpenSSH projection and execution for hub-enrolled hosts.
//!
//! Hub projection, path resolution, OpenSSH syntax policy, managed Include ownership, interactive
//! execution, and private-file publication have separate owners behind the existing flat API.

use crate::ssh_argv::encode_remote_command;
use crate::{AppResult, HubAgent, HubClient, config_path, io_error, resolve_ssh_tool};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// These markers, path components, and aliases are persisted in operator SSH configuration.
const MANAGED_INCLUDE_BEGIN: &str = "# BEGIN onec-ops managed SSH hosts";
const MANAGED_INCLUDE_END: &str = "# END onec-ops managed SSH hosts";
const USER_SSH_CONFIG_MAX_BYTES: usize = 4 * 1024 * 1024;
const GATEWAY_ALIAS: &str = "onec-ops-gateway";

pub(super) fn gateway_alias(index: usize) -> String {
    if index == 0 {
        GATEWAY_ALIAS.to_owned()
    } else {
        format!("{GATEWAY_ALIAS}-{}", index + 1)
    }
}

mod exec;
mod include;
mod io;
mod model;
mod paths;
mod sync;
mod syntax;

pub use exec::{resolve_managed_ssh_agent, run_managed_ssh};
pub use model::{SshHostSkip, SshHostSyncReport};
pub use paths::{
    managed_gateway_known_hosts_path, managed_ssh_config_path, managed_target_known_hosts_path,
    user_ssh_config_path,
};
pub use sync::sync_hub_ssh_hosts;

pub(crate) fn managed_target_host_key_alias(agent: &HubAgent) -> String {
    host_key_alias(agent)
}

use include::install_managed_include;
use io::write_atomic;
use syntax::{
    append_common_security, host_key_alias, normalized_ed25519_public_key, null_known_hosts_path,
    ssh_alias, ssh_argv_path, ssh_path, ssh_scalar,
};

#[cfg(test)]
mod tests;
