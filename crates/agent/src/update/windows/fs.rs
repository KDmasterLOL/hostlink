//! Windows process, file identity, and private ACL primitives for update handoff.

use super::super::invalid;
use super::super::private_fs::{set_private_directory, set_staged_file_permissions};
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
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle, OPEN_EXISTING, SYNCHRONIZE,
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

    struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper is created only for a successful CreateFileW result and owns
            // that handle until Drop.
            unsafe { CloseHandle(self.0) };
        }
    }

    let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if path_wide.contains(&0) {
        return Err(invalid("Windows identity path contains a null character"));
    }
    path_wide.push(0);
    // OPEN_REPARSE_POINT exposes a raced-in reparse point's own identity. BACKUP_SEMANTICS permits
    // opening a directory for attributes; shared access avoids blocking cleanup operations.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(format!(
            "cannot open Windows directory for identity {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    let handle = OwnedHandle(handle);
    query(handle.0, path)
}

#[cfg(windows)]
pub(super) fn same_windows_file(left: &Path, right: &Path) -> io::Result<bool> {
    Ok(windows_file_identity(left, false)? == windows_file_identity(right, false)?)
}

#[cfg(windows)]
pub(super) fn copy_private_synced(source: &Path, destination: &Path) -> io::Result<()> {
    let source_metadata = fs::symlink_metadata(source)?;
    if !source_metadata.is_file() || is_reparse_point(&source_metadata) {
        return Err(invalid("Windows update copy source is not a regular file"));
    }
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    set_staged_file_permissions(
        destination,
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(""),
    )?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    verify_windows_private_file(destination)
}

#[cfg(windows)]
pub(super) fn write_private_synced(destination: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    set_staged_file_permissions(destination, "install.json")?;
    output.write_all(bytes)?;
    output.sync_all()?;
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
    validate_windows_private_acl(path, &metadata)
}

#[cfg(windows)]
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(windows)]
pub(in crate::update) fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory(path)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(invalid("Windows Agent update directory is unsafe"));
    }
    validate_windows_private_acl(path, &metadata)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
pub(in crate::update) fn validate_windows_private_acl(
    path: &Path,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::GetNamedSecurityInfo;

    if metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows updater path is a reparse point"));
    }
    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater path is not owned by the current user",
        ));
    }
    let sddl = windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )
    .map_err(io::Error::other)?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater ACL inherits permissions",
        ));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("Windows updater path has no DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("Windows updater DACL entry is unreadable"))?;
        if matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) && ace.sid() != Some(current.as_ref())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows updater ACL grants access to a foreign owner",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(in crate::update) fn set_windows_private_acl(path: &Path, directory: bool) -> io::Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let current = ConvertSidToStringSid(&current).map_err(io::Error::other)?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", current.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("cannot create private Windows updater DACL"))?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(io::Error::other)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_windows_private_acl(path, &metadata)
}
