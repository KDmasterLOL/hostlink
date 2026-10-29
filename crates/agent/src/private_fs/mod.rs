//! Agent-owned persistent files and OS locks, shared by jobs and enrollment.
//! Temporary directories are unsuitable for state that survives Agent restarts.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::Path,
};

#[cfg(windows)]
pub(crate) mod windows;

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn validate_private_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
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
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owner/private permissions",
            ));
        }
    }
    #[cfg(windows)]
    {
        windows::validate_acl(
            path,
            &metadata,
            windows::AllowedPrincipals::OwnerSystemAdministrators,
            true,
        )?;
        if !directory {
            windows::reject_hardlinks(path)?;
        }
    }
    Ok(())
}

pub(crate) fn restrict_private_path(path: &Path, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    windows::set_acl(path, directory)?;
    validate_private_path(path, directory)
}

pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_path(path, false)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = options.open(path)?;
    restrict_private_path(path, false)?;
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
