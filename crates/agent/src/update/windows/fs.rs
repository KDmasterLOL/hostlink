//! Windows process, file identity, and private ACL primitives for update handoff.

use super::super::invalid;
pub(in crate::update) use super::super::private_fs::create_private_directory;
use super::super::private_fs::{is_reparse_point, open_private_file};
use private_fs::PrivateDir;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

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
            if same_windows_file(&image, installed_executable)? {
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
#[cfg(windows)]
pub(super) fn windows_file_identity(path: &Path, directory: bool) -> io::Result<(u32, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, SYNCHRONIZE,
    };

    fn query(
        handle: windows_sys::Win32::Foundation::HANDLE,
        path: &Path,
    ) -> io::Result<(u32, u64)> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open and `information` is the writable output structure required
        // by GetFileInformationByHandle.
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
            return Err(io::Error::other(format!(
                "cannot read Windows file identity for {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        let index =
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
        if index == 0 {
            return Err(invalid("Windows file identity is invalid"));
        }
        Ok((information.dwVolumeSerialNumber, index))
    }

    if !directory {
        let file = File::open(path).map_err(|error| {
            io::Error::other(format!(
                "cannot open Windows file for identity {}: {error}",
                path.display()
            ))
        })?;
        return query(file.as_raw_handle(), path);
    }

    // OPEN_REPARSE_POINT exposes a raced-in reparse point's own identity. BACKUP_SEMANTICS permits
    // opening a directory for attributes; shared access avoids blocking cleanup operations.
    let handle = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    query(handle.as_raw_handle(), path)
}

#[cfg(windows)]
pub(super) fn same_windows_file(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(windows_file_identity(left, false)? == windows_file_identity(right, false)?)
}

#[cfg(windows)]
pub(super) fn copy_private_synced(source: &Path, destination: &Path) -> io::Result<()> {
    let mut input = open_private_file(source)?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("copy destination has no parent"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("copy destination has no name"))?;
    let mut output = PrivateDir::open(parent)
        .and_then(|dir| dir.create(name))
        .map_err(io::Error::other)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all().map_err(io::Error::other)?;
    drop(output);
    verify_windows_private_file(destination)
}

#[cfg(windows)]
pub(super) fn write_private_synced(destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("write destination has no parent"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("write destination has no name"))?;
    let mut output = PrivateDir::open(parent)
        .and_then(|dir| dir.create(name))
        .map_err(io::Error::other)?;
    output.write_all(bytes)?;
    output.sync_all().map_err(io::Error::other)?;
    drop(output);
    verify_windows_private_file(destination)
}

#[cfg(windows)]
pub(super) fn verify_windows_private_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(invalid(
            "Windows update transaction contains a non-regular file",
        ));
    }
    verify_windows_private_path(path, &metadata)
}

#[cfg(windows)]
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(windows)]
pub(in crate::update) fn verify_windows_private_path(
    path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    if metadata.is_dir() {
        PrivateDir::open(path).map(|_| ()).map_err(io::Error::other)
    } else {
        open_private_file(path)?.verify().map_err(io::Error::other)
    }
}
