//! Windows offline admission shared by the raw updater and local invite repair.
use crate::agent_files::{is_reparse_point, validate_path_has_no_reparse_components};
use crate::package::invalid;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(crate) fn ensure_offline(root: &Path) -> io::Result<()> {
    ensure_separate_offline(root, true)
}

// Invite bootstrap runs its SHA-verified image from a private temporary directory,
// unlike the explicit updater. Both require no task or installed Agent process.
pub(crate) fn ensure_repair_offline(root: &Path) -> io::Result<()> {
    ensure_separate_offline(root, false)
}

fn ensure_separate_offline(root: &Path, updater_beneath_root: bool) -> io::Result<()> {
    crate::service::ensure_update_unregistered(root)?;
    let updater = std::env::current_exe()?;
    validate_path_has_no_reparse_components(&updater)?;
    let metadata = fs::symlink_metadata(&updater)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(invalid("Windows updater must be a regular executable"));
    }
    let updater = updater.canonicalize()?;
    let root = root.canonicalize()?;
    let installed = root.join("bin/hostlink-agent.exe");
    let installed_exists = installed.try_exists()?;
    if (updater_beneath_root && !updater.starts_with(&root))
        || updater.starts_with(root.join("bin"))
        || (installed_exists && same_file::is_same_file(&updater, &installed)?)
        || (updater_beneath_root && !installed_exists)
    {
        return Err(invalid(if updater_beneath_root {
            "Windows update requires a separate executable beneath root, outside bin"
        } else {
            "Windows repair requires a separate verified executable outside installed bin"
        }));
    }
    reject_running_agent(&installed)
}

#[cfg(windows)]
pub(crate) fn reject_running_agent(installed_executable: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE, SetLastError,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    };
    let current_pid = std::process::id();
    // SAFETY: snapshot creation has no pointer arguments and the returned handle is checked.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(format!(
            "cannot enumerate Windows processes before Agent update: {}",
            io::Error::last_os_error()
        )));
    }
    struct Snapshot(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the valid snapshot handle.
            unsafe { CloseHandle(self.0) };
        }
    }
    let snapshot = Snapshot(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: entry is initialized and writable, and snapshot is a valid process snapshot.
    if unsafe { Process32FirstW(snapshot.0, &mut entry) } == 0 {
        return Err(io::Error::other(format!(
            "cannot read Windows process snapshot: {}",
            io::Error::last_os_error()
        )));
    }
    loop {
        let image_name = String::from_utf16_lossy(&entry.szExeFile);
        let image_name = image_name.trim_end_matches('\0');
        if entry.th32ProcessID != current_pid
            && image_name.eq_ignore_ascii_case("hostlink-agent.exe")
        {
            // SAFETY: PID comes from the system process snapshot; handle is closed below.
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID) };
            if process.is_null() {
                return Err(io::Error::other(format!(
                    "cannot establish whether PID {} is the installed Agent",
                    entry.th32ProcessID
                )));
            }
            let mut image = vec![0u16; 32_768];
            let mut length = image.len() as u32;
            // SAFETY: process is valid; image is writable and length gives its UTF-16 capacity.
            let queried =
                unsafe { QueryFullProcessImageNameW(process, 0, image.as_mut_ptr(), &mut length) };
            // SAFETY: process is uniquely owned by this scope.
            unsafe { CloseHandle(process) };
            if queried == 0 {
                return Err(io::Error::other(format!(
                    "cannot establish image path for PID {}",
                    entry.th32ProcessID
                )));
            }
            let image = PathBuf::from(std::ffi::OsString::from_wide(&image[..length as usize]));
            let matches = if installed_executable.try_exists()? {
                same_file::is_same_file(&image, installed_executable)?
            } else {
                same_windows_path(&image.canonicalize()?, installed_executable)?
            };
            if matches {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "installed Agent process is still active",
                ));
            }
        }
        // SAFETY: entry remains writable and snapshot remains valid.
        unsafe { SetLastError(0) };
        if unsafe { Process32NextW(snapshot.0, &mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                return Err(io::Error::other(format!(
                    "Windows process enumeration ended unexpectedly ({error})"
                )));
            }
            break;
        }
    }
    Ok(())
}

fn same_windows_path(image: &Path, expected: &Path) -> io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    // The expected image may be absent. Compare absolute OS-reported paths with
    // Windows ordinal case semantics, accepting the canonical extended prefix.
    let mut left = image.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut right = expected.as_os_str().encode_wide().collect::<Vec<_>>();
    for path in [&mut left, &mut right] {
        if path.starts_with(&[92, 92, 63, 92]) {
            path.drain(..4);
        }
    }
    // SAFETY: both buffers are valid for their explicit UTF-16 lengths; no terminator required.
    let result = unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == CSTR_EQUAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_image_comparison_uses_windows_ordinal_paths() {
        assert!(
            same_windows_path(
                Path::new(r"C:\Users\Owner\Agent\bin\hostlink-agent.exe"),
                Path::new(r"\\?\C:\USERS\Owner\Agent\bin\HOSTLINK-AGENT.EXE")
            )
            .unwrap()
        );
        assert!(
            !same_windows_path(
                Path::new(r"C:\Other\hostlink-agent.exe"),
                Path::new(r"\\?\C:\Users\Owner\Agent\bin\hostlink-agent.exe")
            )
            .unwrap()
        );
    }
}
