//! Windows service lifecycle façade.
//!
//! Platform-specific SCM ownership and service runtime callbacks stay behind this
//! module so the rest of the agent can use one stable lifecycle API.

use std::io;
use std::path::{Path, PathBuf};

/// Stable operating-system service name used by the resident agent.
pub const SERVICE_NAME: &str = "onec-agent";

/// Normalized resident-service lifecycle state.
#[derive(
    Debug,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
    PartialEq,
    Eq,
    strum::Display,
    strum::IntoStaticStr,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum ServiceRuntimeState {
    /// Service is not installed or registered.
    NotInstalled,
    /// Service is installed but stopped.
    Stopped,
    /// Service manager reports startup in progress.
    StartPending,
    /// Service manager reports shutdown in progress.
    StopPending,
    /// Service is running.
    Running,
    /// Service is resuming from a paused state.
    ContinuePending,
    /// Service is transitioning into the paused state.
    PausePending,
    /// Service is paused.
    Paused,
}

impl ServiceRuntimeState {
    /// Returns the stable kebab-case wire/display spelling.
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// Normalized service registration/runtime projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRuntimeStatus {
    /// Whether the operating-system service is installed.
    pub installed: bool,
    /// Current normalized service state.
    pub state: ServiceRuntimeState,
    /// Running service process identifier when available.
    pub process_id: Option<u32>,
}

#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
use unsupported as imp;
#[cfg(windows)]
use windows as imp;

/// Installs the resident agent service for one configuration file.
///
/// # Errors
///
/// Returns an I/O error when service registration/configuration or requested initial startup fails.
pub fn install(config: &Path, start_after_install: bool) -> io::Result<()> {
    imp::install(config, start_after_install)
}

/// Starts the installed resident agent service and returns its resulting state.
///
/// # Errors
///
/// Returns an I/O error when service-manager access or startup fails.
pub fn start() -> io::Result<ServiceRuntimeStatus> {
    imp::start()
}

/// Stops the installed resident agent service and returns its resulting state.
///
/// # Errors
///
/// Returns an I/O error when service-manager access or shutdown fails.
pub fn stop() -> io::Result<ServiceRuntimeStatus> {
    imp::stop()
}

/// Reads the current resident-service registration/runtime state.
///
/// # Errors
///
/// Returns an I/O error when the platform service manager cannot be queried.
pub fn status() -> io::Result<ServiceRuntimeStatus> {
    imp::status()
}

/// Removes the resident service registration, optionally stopping it first.
///
/// # Errors
///
/// Returns an I/O error when requested shutdown or service deletion fails.
pub fn uninstall(stop_before_delete: bool) -> io::Result<()> {
    imp::uninstall(stop_before_delete)
}

/// Enters the operating-system service runtime using the supplied agent configuration.
///
/// # Errors
///
/// Returns an I/O error when service dispatch, configuration loading, or runtime execution fails.
pub fn dispatch(config: PathBuf) -> io::Result<()> {
    imp::dispatch(config)
}

#[cfg(test)]
mod tests {
    use super::ServiceRuntimeState;

    #[test]
    fn service_runtime_state_json_contract_covers_every_variant() {
        let cases = [
            (ServiceRuntimeState::NotInstalled, "not-installed"),
            (ServiceRuntimeState::Stopped, "stopped"),
            (ServiceRuntimeState::StartPending, "start-pending"),
            (ServiceRuntimeState::StopPending, "stop-pending"),
            (ServiceRuntimeState::Running, "running"),
            (ServiceRuntimeState::ContinuePending, "continue-pending"),
            (ServiceRuntimeState::PausePending, "pause-pending"),
            (ServiceRuntimeState::Paused, "paused"),
        ];
        for (state, spelling) in cases {
            assert_eq!(state.as_str(), spelling);
            assert_eq!(
                serde_json::to_string(&state).expect("serialize"),
                format!("\"{spelling}\"")
            );
            assert_eq!(
                serde_json::from_str::<ServiceRuntimeState>(&format!("\"{spelling}\""))
                    .expect("deserialize"),
                state
            );
            assert_eq!(state.to_string(), spelling);
        }
    }
}
