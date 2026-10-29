//! Current-user Task Scheduler lifecycle. No private service record or IPC.
use super::ServiceStatus;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};

mod enrollment;
mod legacy;
mod lifecycle;
mod private_fs;
mod scheduler;
mod task_xml;
use enrollment::*;
pub use lifecycle::{install, remove, start, status, stop};
use private_fs::*;

pub fn ensure_update_unregistered(root: &Path) -> io::Result<()> {
    ensure_user_scope()?;
    let root = verify_install_root(root)?;
    legacy::reject(&root)?;
    if scheduler::Scheduler::connect()?
        .task(&task_name(&root)?)?
        .is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "offline Windows update requires service stop and service remove before update; reinstall the task afterwards",
        ));
    }
    Ok(())
}

pub fn validate_update_root(root: &Path) -> io::Result<()> {
    let root = verify_install_root(root)?;
    let expected = local_app_data_path()?.join("HostLink/Agent");
    if fs::canonicalize(expected)? != root {
        return Err(invalid(
            "Agent updater root must be the exact OS-owned LocalAppData/HostLink/Agent directory",
        ));
    }
    ensure_update_unregistered(&root)
}

fn root_digest(root: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(root.as_os_str().to_string_lossy().as_bytes())
    )[..24]
        .into()
}
fn task_name(root: &Path) -> io::Result<String> {
    Ok(format!(
        "HostLinkAgent-v2-{}-{}",
        current_sid()?,
        root_digest(root)
    ))
}
fn agent_executable(root: &Path) -> PathBuf {
    root.join("bin/hostlink-agent.exe")
}
