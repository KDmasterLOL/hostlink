use super::*;

#[cfg(windows)]
pub(super) fn reject_windows_parent_reparse_components(parent: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::path::{Component, Prefix};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if !parent.is_absolute() {
        return Err(invalid("Agent install root parent must be absolute"));
    }
    let mut ancestor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => {
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(invalid(
                        "Agent install root must be on a local Windows drive",
                    ));
                }
                ancestor.push(component.as_os_str());
            }
            Component::RootDir => ancestor.push(component.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(invalid("Agent install root parent contains path traversal"));
            }
            Component::Normal(_) => {
                ancestor.push(component.as_os_str());
                let metadata = fs::symlink_metadata(&ancestor)?;
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(invalid(
                        "Agent install root parent contains a symlink or reparse point",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn reject_elevated_user() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must run as a normal user",
            ));
        }
    }
    #[cfg(windows)]
    windows_elevation::reject_elevated_user()?;
    Ok(())
}

#[cfg(windows)]
mod windows_elevation {
    use std::{io, mem::size_of};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    pub fn reject_elevated_user() -> io::Result<()> {
        let current_sid =
            windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
        let system_sid: windows_permissions::LocalBox<windows_permissions::Sid> =
            "S-1-5-18".parse().map_err(io::Error::other)?;
        if current_sid.as_ref() == system_sid.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must not run as SYSTEM",
            ));
        }
        // SAFETY: all handles and output buffers follow the Win32 token API contracts.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::from_raw_os_error(GetLastError() as i32));
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            let last_error = GetLastError();
            CloseHandle(token);
            if result == 0 {
                return Err(io::Error::from_raw_os_error(last_error as i32));
            }
            if elevation.TokenIsElevated != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "enrollment must not run elevated or as SYSTEM",
                ));
            }
        }
        Ok(())
    }
}
