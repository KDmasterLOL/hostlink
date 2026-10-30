//! Cleanup guard only for fresh disposable staging, never recovery transactions.

use private_fs::PrivateDir;
use std::{
    io,
    path::{Path, PathBuf},
};

pub(in crate::update) struct PrivateTempDir {
    path: PathBuf,
    cleanup: bool,
}

impl PrivateTempDir {
    pub(in crate::update) fn new_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        let name = format!("{prefix}{}", uuid::Uuid::new_v4());
        // Create with private security at birth; inherited Windows ACLs are insufficient.
        PrivateDir::open(parent)
            .and_then(|dir| dir.create_dir(&name))
            .map_err(io::Error::other)?;
        Ok(Self {
            path: parent.join(name),
            cleanup: true,
        })
    }

    pub(in crate::update) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    pub(in crate::update) fn preserve(&mut self) {
        self.cleanup = false;
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        if !self.cleanup {
            return;
        }
        // Refuse cleanup if the owned staging root has become a link or lost privacy.
        let cleanup = PrivateDir::open(&self.path)
            .map_err(io::Error::other)
            .and_then(|dir| {
                drop(dir);
                std::fs::remove_dir_all(&self.path)
            });
        if let Err(error) = cleanup {
            eprintln!(
                "private Agent staging cleanup failed at {}: {error}",
                self.path.display()
            );
        }
    }
}
