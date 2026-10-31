//! Verified PrivateFile to standard File bridge for OS locks and Tokio.
//! Private path, ownership and ACL policy remain in the private-fs crate.

use private_fs::PrivateFile;
use std::{fs::File, io};

/// Clone the verified handle for APIs requiring a standard File (locking/Tokio).
/// The clone refers to the acquired object; it never reopens its pathname.
pub(crate) trait PrivateFileExt {
    fn try_clone_std(&self) -> io::Result<File>;
}

impl PrivateFileExt for PrivateFile {
    fn try_clone_std(&self) -> io::Result<File> {
        self.verify().map_err(io::Error::other)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            Ok(self.as_fd().try_clone_to_owned()?.into())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            Ok(self.as_handle().try_clone_to_owned()?.into())
        }
    }
}

#[cfg(test)]
#[path = "private_fs_tests.rs"]
mod tests;
