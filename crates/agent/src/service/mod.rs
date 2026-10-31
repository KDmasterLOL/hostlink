//! Current-user lifecycle delegated to the operating system.
//! SSH, enrollment and package integrity are separate Agent concerns.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    pub installed: bool,
    pub active: bool,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod offline;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{install, remove, start, status, stop};
#[cfg(windows)]
pub use windows::{install, remove, start, status, stop};

#[cfg(windows)]
pub(crate) use windows::ensure_update_unregistered;
#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("HostLink Agent service lifecycle supports Linux and Windows only");
#[cfg(windows)]
pub(crate) use offline::ensure_offline as ensure_agent_offline;
