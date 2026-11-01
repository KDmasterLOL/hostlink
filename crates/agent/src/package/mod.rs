//! Minimal runnable-file validation shared by installation and service lifecycle.

use crate::agent_files::is_reparse_point;
use std::{fs, io, path::Path};

pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const EXECUTABLE_NAME: &str = if cfg!(windows) {
    "hostlink-agent.exe"
} else {
    "hostlink-agent"
};

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Service registration validates its runnable file without imposing data-file ACLs on bin.
pub(crate) fn verify_executable(path: &Path) -> io::Result<()> {
    let parent = fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| invalid("executable has no parent"))?,
    )?;
    let metadata = fs::symlink_metadata(path)?;
    if !parent.is_dir()
        || parent.file_type().is_symlink()
        || is_reparse_point(&parent)
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(invalid("Agent executable is not a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads the process identity and has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7022 != 0
            || metadata.permissions().mode() & 0o100 == 0
        {
            return Err(invalid(
                "Agent executable must be owned, single-link and owner-executable",
            ));
        }
    }
    Ok(())
}
