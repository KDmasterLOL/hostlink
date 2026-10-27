use super::ServiceStatus;
use crate::jobs;
use sha2::{Digest, Sha256};
use std::os::windows::fs::MetadataExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    process::{Command, Stdio},
    time::Duration,
};
use std::{
    io,
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
    Storage::FileSystem::SYNCHRONIZE,
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW,
    },
    System::{
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW, WaitForSingleObject,
        },
    },
    UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW},
};

const MARKER: &str = ".hostlink-user-service.json";
const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const MARKER_FORMAT: u32 = 1;
const MAX_MARKER: usize = 16 * 1024;
const MAX_PIPE_MESSAGE: usize = 1024;
const MAINTENANCE_ADMISSION: &str = ".hostlink-maintenance-admission.json";
const MAX_MAINTENANCE_ADMISSION: usize = 4096;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallRecord {
    format: u32,
    owner_sid: String,
    root: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
    config: PathBuf,
    launcher_executable: PathBuf,
    startup_script: PathBuf,
    startup_script_sha256: String,
    pipe_name: String,
    control_token: String,
    run_value: String,
    #[serde(default)]
    maintenance: bool,
    #[serde(default)]
    maintenance_previous_sha256: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MaintenanceAdmission {
    format: u32,
    transaction_id: String,
    root: PathBuf,
    owner_sid: String,
    executable_sha256: String,
    capability_sha256: String,
}
/// Opaque, in-process evidence captured before the login registration is disabled.
/// The durable marker retains the prior executable digest for crash-safe rollback.
#[must_use = "retain the receipt through publication, registration, and any rollback"]
pub(super) struct MaintenanceReceipt {
    pub(super) old_marker: Vec<u8>,
    pub(super) old_record: InstallRecord,
    pub(super) run_command: String,
    pub(super) transaction_id: String,
}

mod admission;
mod lifecycle;
mod maintenance;
mod private_fs;
mod process;
mod registration;

use admission::*;
use lifecycle::*;
pub(super) use lifecycle::{
    control_loop, ensure_update_unregistered, install, remove, start, status, stop,
    validate_managed_run, validate_update_root,
};
use maintenance::*;
pub(crate) use maintenance::{
    begin_maintenance, begin_recovery_maintenance, has_registration, is_in_maintenance,
    recover_maintenance_after_inventory, recover_maintenance_stop, register_maintenance,
    restore_maintenance, start_maintenance_candidate, stop_for_maintenance_rollback,
    update_maintenance_executable, verify_registered_health, verify_registered_image,
};
use private_fs::*;
use process::*;
use registration::*;

#[cfg(test)]
mod tests;
