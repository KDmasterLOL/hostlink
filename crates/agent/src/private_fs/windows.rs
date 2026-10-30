//! OS profile lookup for Windows 7; private-fs owns filesystem security.

use std::{io, os::windows::ffi::OsStringExt, path::PathBuf};

/// OS-resolved profile path, independent of caller-supplied environment variables.
/// SHGetFolderPathW is available on NT6.1 and avoids the Windows 7 combase import.
pub(crate) fn local_app_data_path() -> io::Result<PathBuf> {
    use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};

    let mut buffer = [0u16; 260];
    // SAFETY: SHGetFolderPathW writes at most MAX_PATH UTF-16 units into this buffer.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            CSIDL_LOCAL_APPDATA as i32,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    windows::core::HRESULT(result)
        .ok()
        .map_err(io::Error::other)?;
    let end = buffer.iter().position(|&unit| unit == 0).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "unterminated LocalAppData path")
    })?;
    PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end])).canonicalize()
}
