//! Private filesystem operations shared by Agent update paths.

#[cfg(unix)]
use super::EXECUTABLE_BASE;
use super::manifest::FileIdentity;
use super::{MAX_ENTRY_BYTES, MAX_TOTAL_BYTES, invalid};
use private_fs::{PrivateDir, PrivateFile};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

pub(super) fn validate_user_owned_root(root: &Path) -> io::Result<()> {
    validate_path_has_no_reparse_components(root)?;
    #[cfg(not(windows))]
    {
        PrivateDir::open(root).map_err(io::Error::other)?;
        if fs::canonicalize(root)? != root {
            return Err(invalid("Agent install root must not use a symlinked path"));
        }
    }
    #[cfg(windows)]
    return validate_windows_update_root(root);
    #[cfg(not(windows))]
    Ok(())
}

#[cfg(windows)]
fn validate_windows_update_root(root: &Path) -> io::Result<()> {
    let profile = local_app_data_path()?;
    let parent = profile.join("HostLink");
    let expected = parent.join("Agent");
    PrivateDir::open(root).map_err(io::Error::other)?;
    PrivateDir::open(&parent).map_err(io::Error::other)?;
    if expected.canonicalize()? != root.canonicalize()? {
        return Err(invalid(
            "Agent updater root must be the exact current-user LocalAppData/HostLink/Agent",
        ));
    }
    crate::service::ensure_update_unregistered(&expected)
}

// The updater has an exact per-user install location; keep profile lookup
// independent of caller-provided environment variables. SHGetFolderPathW
// avoids importing newer Known Folder functions on the Win7 build.
#[cfg(windows)]
fn local_app_data_path() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};

    let mut buffer = [0u16; 260];
    // SAFETY: SHGetFolderPathW writes at most MAX_PATH UTF-16 units.
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

pub(super) fn file_identities(
    root: &Path,
    names: &[String],
) -> io::Result<BTreeMap<String, FileIdentity>> {
    let mut result = BTreeMap::new();
    let mut total_size = 0_u64;
    for name in names {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid("installed Agent package file is missing or unsafe"));
        }
        if metadata.len() > MAX_ENTRY_BYTES {
            return Err(invalid(
                "installed Agent package file exceeds its size limit",
            ));
        }
        total_size = total_size
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("installed Agent package size overflow"))?;
        if total_size > MAX_TOTAL_BYTES {
            return Err(invalid(
                "installed Agent package exceeds its total size limit",
            ));
        }
        // Binaries and support scripts are nonsecret. Persistent state/keys retain private-fs.
        let mut hasher = Sha256::new();
        let size = io::copy(
            &mut File::open(&path)?.take(MAX_ENTRY_BYTES + 1),
            &mut hasher,
        )?;
        if size > MAX_ENTRY_BYTES {
            return Err(invalid(
                "installed Agent package file grew beyond its size limit",
            ));
        }
        result.insert(
            name.clone(),
            FileIdentity {
                size,
                sha256: format!("{:x}", hasher.finalize()),
            },
        );
    }
    Ok(result)
}

pub(super) fn hash_file(path: &Path, max_size: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > max_size {
        return Err(invalid("Agent archive exceeds its size limit"));
    }
    let mut hasher = Sha256::new();
    let copied = io::copy(&mut file.take(max_size + 1), &mut hasher)?;
    if copied > max_size {
        return Err(invalid("Agent file grew beyond its size limit"));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(super) fn open_private_file(path: &Path) -> io::Result<PrivateFile> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("private file has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("private file has no name"))?;
    PrivateDir::open(parent)
        .and_then(|dir| dir.open_file(name))
        .map_err(io::Error::other)
}

#[cfg(not(windows))]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    PrivateDir::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(io::Error::other)
}

pub(super) fn set_staged_file_permissions(path: &Path, relative: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Only freshly extracted files in our private staging tree are adopted here.
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        private_fs::harden(&file).map_err(io::Error::other)?;
        if relative == EXECUTABLE_BASE {
            // private-fs requires regular files to be exactly 0600. The executable alone
            // needs 0700 and is subsequently verified by the executable-specific contract.
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
        } else {
            private_fs::verify(&file).map_err(io::Error::other)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = relative;
        open_private_file(path)?
            .verify()
            .map_err(io::Error::other)?;
    }
    Ok(())
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
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid(
                "bootstrap path contains a symlink or reparse point",
            ));
        }
    }
    Ok(())
}

// Fresh bootstrap still verifies its private output/state; installed update bundles do not use this.
#[cfg(windows)]
pub(super) fn verify_windows_private_path(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.is_dir() {
        PrivateDir::open(path).map(|_| ()).map_err(io::Error::other)
    } else {
        open_private_file(path)?.verify().map_err(io::Error::other)
    }
}
