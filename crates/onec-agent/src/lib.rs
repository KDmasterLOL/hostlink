//! Resident target agent runtime, control server, durable jobs, managed SSH tunnel, and service lifecycle.
//!
//! The library owns target-local execution and transport mechanics. Controller-side topology,
//! project/1C policy, and release orchestration remain outside the agent boundary.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod config;
mod control;
mod diagnostics;
/// Embedded library-owned SSH/SFTP target transport boundary.
pub mod embedded_ssh;
/// HTTPS-only fresh-install enrollment transport for a verified agent candidate.
mod enrollment_http;
/// Child-process environment isolation and request-owned environment policy.
mod environment;
/// Durable structured job persistence and worker lifecycle.
mod jobs;
/// Managed installed-runtime update policy and library-backed bundle replacement.
mod managed_update;
/// Dedicated Ed25519 key and run-local terminal attestation boundary.
mod native_attestation;
mod network;
/// Target-owned managed result artifact publication and retrieval.
mod results;
mod service;
mod tunnel;

use hostlink_core::{
    OwnedProcess, RedactingWriter, background_command, constant_time_str_eq, system_hostname,
};
use onec_agent_protocol::{
    AgentErrorCode, AgentRequest, AgentRequestKind, AgentResponse, AgentResponseKind,
    PROTOCOL_VERSION, write_json_line,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use config::validate_user_sshd_config;
pub use config::{
    AgentConfig, EmbeddedSshServerConfig, SshGatewayEndpoint, SshServerConfig, SshTlsProxyConfig,
    SshTunnelConfig,
};
use control::serve_listener;
pub use control::{AgentRuntime, handle_connection, serve};
#[cfg(windows)]
use diagnostics::set_agent_event_log_path;
#[cfg(test)]
use diagnostics::{AGENT_EVENT_SCHEMA_VERSION, write_agent_event};
use diagnostics::{AgentEventFields, agent_event};
pub use enrollment_http::post_enrollment_json;
use network::{bridge_tcp, connect_target};

#[cfg(windows)]
pub(crate) use tunnel::run_with_tunnel_until;
pub use tunnel::{TunnelChild, probe_tunnel, run_with_tunnel};

/// Runs the isolated user-mode sshd host used by the managed Windows tunnel path.
///
/// # Errors
///
/// Returns [`std::io::Error`] when the sshd host/start-gate lifecycle cannot be established.
pub fn run_sshd_host(program: &Path, config: &Path, start_event: &str) -> io::Result<u32> {
    tunnel::run_sshd_host(program, config, start_event)
}

pub use service::{
    SERVICE_NAME, ServiceRuntimeState, ServiceRuntimeStatus, dispatch as run_service,
    install as install_service, start as start_service, status as service_status,
    stop as stop_service, uninstall as uninstall_service,
};

pub use managed_update::{
    AgentPackageUpdateRequest, DirectPackageUpdateRequest, RuntimeUpdateOutcome,
    RuntimeUpdatePreflightOutcome, preflight_runtime_update, update_agent_package,
    update_direct_package,
};

/// Runs the durable-job worker for one already-created agent job directory.
///
/// # Errors
///
/// Returns [`std::io::Error`] when job state, child execution, durable logs, or terminal-state
/// publication fails.
pub async fn run_job_worker(job_dir: impl AsRef<Path>) -> io::Result<()> {
    jobs::run_worker(job_dir.as_ref()).await
}

#[cfg(test)]
mod tests;
