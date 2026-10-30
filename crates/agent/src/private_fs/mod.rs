//! Minimal OS-handle glue for Agent-private files and process locks.
//! Privacy, path traversal and creation policy belong to the private-fs crate.

use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir, PrivateFile};
use std::{fs::File, io, path::Path};

#[cfg(windows)]
pub(crate) mod windows;

/// Clone the verified handle for APIs requiring a standard File (locking/Tokio).
/// The clone refers to the acquired object; it never reopens its pathname.
pub(crate) fn open_file_std(file: &PrivateFile) -> io::Result<File> {
    file.verify().map_err(io::Error::other)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(file.as_fd().try_clone_to_owned()?.into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(file.as_handle().try_clone_to_owned()?.into())
    }
}

pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lock path has no file name"))?;
    let directory = PrivateDir::open(std::path::absolute(parent)?).map_err(io::Error::other)?;
    let file = directory
        .open_file_with(
            name,
            OpenOptions {
                access: FileAccess::ReadWrite,
                creation: FileCreation::OpenOrCreate,
                ..OpenOptions::default()
            },
        )
        .map_err(io::Error::other)?;
    open_file_std(&file)
}

#[cfg(test)]
mod tests;
