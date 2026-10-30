//! Private filesystem operations shared by Agent update paths.

#[cfg(not(windows))]
use super::EXECUTABLE_BASE;
use super::manifest::FileIdentity;
#[cfg(windows)]
use super::windows::{set_windows_private_acl, validate_windows_private_acl};
use super::{MAX_ENTRY_BYTES, MAX_TOTAL_BYTES, invalid};
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use std::io::Write;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

pub(super) fn validate_user_owned_root(root: &Path) -> io::Result<()> {
    crate::private_fs::validate_private_path(root, true)?;
    if fs::canonicalize(root)? != root {
        return Err(invalid("Agent install root must not use a symlinked path"));
    }
    #[cfg(windows)]
    {
        let metadata = fs::symlink_metadata(root)?;
        validate_windows_update_root(root)?;
        validate_windows_private_acl(root, &metadata)?;
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_update_root(root: &Path) -> io::Result<()> {
    let root = crate::private_fs::windows::validate_agent_root(root)?;
    let expected = crate::private_fs::windows::local_app_data_path()?.join("HostLink/Agent");
    if expected.canonicalize()? != root {
        return Err(invalid(
            "Agent updater root must be the exact current-user LocalAppData/HostLink/Agent",
        ));
    }
    crate::service::ensure_update_unregistered(&root)
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(invalid(
                    "installed Agent package file has an unexpected hard link",
                ));
            }
        }
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut hasher)?;
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
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > max_size {
        return Err(invalid("Agent archive exceeds its size limit"));
    }
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

pub(super) fn open_private_file(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let metadata = fs::symlink_metadata(path);
    if let Ok(metadata) = metadata
        && (!metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata))
    {
        return Err(invalid(
            "Agent updater state file is not a safe regular file",
        ));
    }
    options.open(path)
}

#[cfg(not(windows))]
pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("metadata path has no parent"))?;
    let mut staged = tempfile::Builder::new()
        .prefix(".install-")
        .tempfile_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
pub(super) use crate::private_fs::sync_directory;

#[cfg(not(windows))]
pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            validate_private_directory(path, &metadata)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
pub(super) fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    let _ = metadata;
    crate::private_fs::validate_private_path(path, true)
}

pub(super) fn set_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    set_windows_private_acl(path, true)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

pub(super) fn set_staged_file_permissions(path: &Path, relative: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if relative == EXECUTABLE_BASE {
            0o700
        } else {
            0o600
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let _ = relative;
        set_windows_private_acl(path, false)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (path, relative);
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
