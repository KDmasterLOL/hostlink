//! Agent-owned persistent files and OS locks, shared by jobs and enrollment.
//! Temporary directories are unsuitable for state that survives Agent restarts.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
#[cfg(any(unix, test))]
use std::fs;
use std::{
    fs::File,
    io,
    path::{Component, Path},
};

#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_file(file: &mut File, directory: bool, restrict: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink()
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err(invalid(
            "private path is a symlink or has the wrong file type",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads process identity and takes no pointers.
        if metadata.uid() != unsafe { libc::geteuid() }
            || (!directory && metadata.nlink() != 1)
            || (!restrict && metadata.permissions().mode() & 0o077 != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owner/private permissions or hard links",
            ));
        }
        if restrict {
            let mode = if directory { 0o700 } else { 0o600 };
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("Windows private path is a reparse point"));
        }
        if !directory {
            windows::reject_file_hardlinks(file)?;
        }
        if restrict {
            windows::set_file_acl(file, directory)?;
        } else {
            windows::validate_file_acl(
                file,
                windows::AllowedPrincipals::OwnerSystemAdministrators,
                true,
            )?;
        }
    }
    Ok(())
}

/// Open and verify the actual private object once, then use its handle.
pub(crate) fn open_private(path: &Path, directory: bool) -> io::Result<File> {
    let mut file = open_path(path, false)?;
    check_file(&mut file, directory, false)?;
    Ok(file)
}

/// Open a directory without symlink/reparse components; this does not validate ownership or permissions.
/// # Errors
/// Rejects traversal, links, reparse points and paths that cannot be opened as directories.
pub(crate) fn open_directory(path: &Path) -> io::Result<Dir> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid("private path contains parent traversal"));
    }
    let path = std::path::absolute(path)?;
    let root = path
        .ancestors()
        .last()
        .ok_or_else(|| invalid("private path has no root"))?;
    let mut directory = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        directory = directory.open_dir_nofollow(name)?;
        #[cfg(windows)]
        {
            use cap_std::fs::MetadataExt;
            if directory.dir_metadata()?.file_attributes() & 0x400 != 0 {
                return Err(invalid("private directory is a reparse point"));
            }
        }
    }
    Ok(directory)
}

fn open_path(path: &Path, restrict: bool) -> io::Result<File> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid("private path contains parent traversal"));
    }
    // The basename drops trailing / and /. before applying nofollow.
    let path = std::path::absolute(path)?;
    let parent = open_directory(path.parent().unwrap_or(&path))?;
    let name = path.file_name().unwrap_or(std::ffi::OsStr::new("."));
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        let _ = restrict;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        options
            .access_mode(
                READ_CONTROL
                    | FILE_READ_ATTRIBUTES
                    | FILE_READ_DATA
                    | if restrict { WRITE_DAC } else { 0 },
            )
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    Ok(parent.open_with(name, &options)?.into_std())
}

pub(crate) fn restrict_private_path(path: &Path, directory: bool) -> io::Result<()> {
    check_file(&mut open_path(path, true)?, directory, true)
}

pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| invalid("lock path has no file name"))?;
    // Ambient authority ends at the parent. Validate the actual opened directory,
    // and never resolve or change the lock by its ambient pathname afterwards.
    let mut directory = open_directory(parent)?.into_std_file();
    check_file(&mut directory, true, false)?;
    let directory = Dir::from_std_file(directory);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::*,
        };
        options
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let (file, created) = match directory.open_with(name, &options) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            (directory.open_with(name, options.create_new(false))?, false)
        }
        Err(error) => return Err(error),
    };
    let mut file = file.into_std();
    check_file(&mut file, false, created)?;
    Ok(file)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests;
