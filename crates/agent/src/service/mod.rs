//! User-scoped Agent lifecycle integration.
//!
//! Linux uses only `systemctl --user`; this module never contacts the system
//! manager or changes login lingering. The service record binds a unit to the
//! exact private install root, executable digest, config and current uid.

#[cfg(not(target_os = "linux"))]
use std::{io, path::Path};

#[derive(Debug)]
pub struct ServiceStatus {
    pub installed: bool,
    pub active: bool,
    pub owner_uid: Option<u32>,
    pub owner_sid: Option<String>,
    pub pid: Option<u32>,
    pub executable_sha256: Option<String>,
    pub ssh_banner: bool,
    pub local_enrollment: bool,
    pub detail: String,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{install, remove, start, status, stop};

#[cfg(windows)]
pub use windows::{install, remove, start, status, stop};

#[cfg(windows)]
#[allow(dead_code)] // Consumed by the separately owned Windows updater integration.
pub(crate) use windows::{
    begin_maintenance, begin_recovery_maintenance, has_registration, is_in_maintenance,
    recover_maintenance_after_inventory, recover_maintenance_stop, register_maintenance,
    restore_maintenance, start_maintenance_candidate, stop_for_maintenance_rollback,
    update_maintenance_executable, verify_registered_health, verify_registered_image,
};

#[cfg(not(any(target_os = "linux", windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "persistent Agent lifecycle is supported on Linux systemd --user and Windows current-user login startup only",
    )
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn install(_: &Path, _: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn start(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn stop(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn remove(_: &Path) -> io::Result<()> {
    Err(unsupported())
}
#[cfg(not(any(target_os = "linux", windows)))]
pub fn status(_: &Path) -> io::Result<ServiceStatus> {
    Err(unsupported())
}

#[cfg(windows)]
pub async fn control_loop(
    config: &crate::AgentConfig,
    pipe_name: String,
    token: String,
    shutdown: tokio_util::sync::CancellationToken,
    finished: tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    windows::control_loop(config, pipe_name, token, shutdown, finished).await
}
#[cfg(windows)]
pub fn validate_managed_run(
    config: &Path,
    maintenance_start: bool,
) -> io::Result<(String, String)> {
    windows::validate_managed_run(config, maintenance_start)
}
#[cfg(windows)]
pub fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
    windows::ensure_update_unregistered(root)
}
#[cfg(windows)]
pub(crate) fn validate_windows_update_root(root: &Path) -> io::Result<()> {
    windows::validate_update_root(root)
}
