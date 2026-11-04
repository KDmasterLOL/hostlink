//! Private filesystem operations shared by Agent update paths.

use crate::package::invalid;
use private_fs::PrivateDir;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

pub(super) fn validate_user_owned_root(root: &Path) -> io::Result<()> {
    validate_path_has_no_reparse_components(root)?;
    PrivateDir::open(root).map_err(io::Error::other)?;
    #[cfg(not(windows))]
    {
        if fs::canonicalize(root)? != root {
            return Err(invalid("Agent install root must not use a symlinked path"));
        }
    }
    Ok(())
}

// The updater has an exact per-user install location; keep profile lookup
// independent of caller-provided environment variables. SHGetFolderPathW
// avoids importing newer Known Folder functions on the Win7 build.
#[cfg(windows)]
pub(super) fn local_app_data_path() -> io::Result<PathBuf> {
    use windows_sys::Win32::UI::Shell::CSIDL_LOCAL_APPDATA;
    app_data_path(CSIDL_LOCAL_APPDATA as i32)
}

#[cfg(windows)]
fn app_data_path(folder: i32) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::SHGetFolderPathW;

    let mut buffer = [0u16; 260];
    // SAFETY: SHGetFolderPathW writes at most MAX_PATH UTF-16 units.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            folder,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    windows::core::HRESULT(result)
        .ok()
        .map_err(io::Error::other)?;
    let end = buffer.iter().position(|&unit| unit == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unterminated application data path",
        )
    })?;
    PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end])).canonicalize()
}

pub(super) fn hash_file(path: &Path, max_size: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > max_size {
        return Err(invalid(
            "Agent executable is empty or exceeds its size limit",
        ));
    }
    let mut hasher = Sha256::new();
    let copied = io::copy(&mut file.take(max_size + 1), &mut hasher)?;
    if copied > max_size {
        return Err(invalid("Agent file grew beyond its size limit"));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(windows)]
pub(super) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
pub(super) fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

pub(super) fn validate_path_has_no_reparse_components(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "bootstrap path must be absolute and contain no traversal",
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        #[cfg(windows)]
        if matches!(component, Component::Prefix(_)) {
            // A canonical Win7 path begins with \\?\C:. This prefix alone
            // is not an openable filesystem root (ERROR_INVALID_FUNCTION).
            // The next RootDir checks \\?\C:\ before any child is trusted.
            continue;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid(
                "bootstrap path contains a symlink or reparse point",
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
#[path = "agent_files_tests.rs"]
mod tests;
