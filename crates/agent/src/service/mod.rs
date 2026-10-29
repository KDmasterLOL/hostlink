//! User-scoped Agent lifecycle integration.
//!
//! Linux uses service-manager's user-scoped systemd integration without login
//! lingering or a custom PID/marker registry. Windows delegates lifecycle to a
//! limited current-user Task Scheduler logon task. Both preserve Agent data.

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

#[cfg(not(any(target_os = "linux", windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "persistent Agent lifecycle is supported on Linux systemd --user and Windows current-user Task Scheduler only",
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

/// Require absence of both the Windows task and legacy lifecycle registration.
/// # Errors
/// Returns an error for unsafe roots, legacy files/Run values, any installed task,
/// or an unavailable Scheduler; this function never unregisters anything.
#[cfg(windows)]
pub fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
    windows::ensure_update_unregistered(root)
}
#[cfg(windows)]
pub(crate) fn validate_windows_update_root(root: &Path) -> io::Result<()> {
    windows::validate_update_root(root)
}

#[cfg(all(test, not(windows)))]
#[path = "windows/task_xml.rs"]
mod task_xml;
