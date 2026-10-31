//! Bounded SFTP rooted in the configured Agent-owned directory.
use crate::private_fs::PrivateFileExt;
use private_fs::{Durability, FileAccess, FileCreation, OpenOptions, PrivateDir};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 1024 * 1024;
const MAX_OPEN_FILES: usize = 64;
const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRANSFERS: usize = 128;

pub(super) struct OpenFile {
    pub(super) file: tokio::fs::File,
    pub(super) writable: bool,
    pub(super) readable: bool,
}

pub(super) struct SftpSession {
    pub(super) files: HashMap<String, OpenFile>,
    pub(super) next_handle: u64,
    pub(super) root: PathBuf,
    _session_slot: OwnedSemaphorePermit,
}

impl SftpSession {
    pub(super) fn new(
        jobs_root: &Path,
        owner: &str,
        slot: OwnedSemaphorePermit,
    ) -> io::Result<Self> {
        if owner.len() != 64
            || !owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid controller fingerprint",
            ));
        }
        let install = jobs_root.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "jobs root has no parent")
        })?;
        PrivateDir::open(install)
            .and_then(|directory| directory.ensure_dir("transfers"))
            .and_then(|directory| directory.ensure_dir(owner))
            .map_err(io::Error::other)?;
        let root = install.join("transfers").join(owner);
        Ok(Self {
            files: HashMap::new(),
            next_handle: 0,
            root,
            _session_slot: slot,
        })
    }

    pub(super) async fn resolve(&self, path: &str, create: bool) -> Result<PathBuf, StatusCode> {
        let directory = self.private_directory()?;
        let relative = Path::new(path);
        let mut parts = relative.components();
        if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
            return Err(StatusCode::PermissionDenied);
        }
        match directory.open_file(relative) {
            Ok(file) => {
                let metadata = file
                    .try_clone_std()
                    .and_then(|file| file.metadata())
                    .map_err(status_from_io)?;
                if metadata.len() > MAX_TRANSFER_BYTES {
                    return Err(StatusCode::PermissionDenied);
                }
            }
            Err(private_fs::Error::Io(error))
                if create && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(status_from_private(error)),
        }
        Ok(self.root.join(relative))
    }

    pub(super) async fn upload_count(&self) -> Result<usize, StatusCode> {
        let directory = self.private_directory()?;
        let entries = directory.entries().map_err(status_from_private)?;
        if entries.len() > MAX_TRANSFERS {
            return Err(StatusCode::Failure);
        }
        for entry in &entries {
            directory.open_file(entry).map_err(status_from_private)?;
        }
        Ok(entries.len())
    }

    fn private_directory(&self) -> Result<PrivateDir, StatusCode> {
        let transfers = self.root.parent().ok_or(StatusCode::PermissionDenied)?;
        let install = transfers.parent().ok_or(StatusCode::PermissionDenied)?;
        let owner = self.root.file_name().ok_or(StatusCode::PermissionDenied)?;
        PrivateDir::open(install)
            .and_then(|directory| directory.open_dir("transfers"))
            .and_then(|directory| directory.open_dir(owner))
            .map_err(status_from_private)
    }

    pub(super) fn handle(&mut self) -> String {
        let h = format!("f{:016x}", self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }
}

mod handler;

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}
fn status_from_io(e: io::Error) -> StatusCode {
    match e.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StatusCode::BadMessage,
        _ => StatusCode::Failure,
    }
}

#[cfg(all(test, unix))]
mod tests;

fn status_from_private(error: private_fs::Error) -> StatusCode {
    match error {
        private_fs::Error::Io(error) => status_from_io(error),
        _ => StatusCode::PermissionDenied,
    }
}
