//! Bounded SFTP rooted in the configured Agent-owned directory.
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

#[cfg(windows)]
use crate::private_fs::windows::set_acl as set_private_acl;

const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 1024 * 1024;
const MAX_OPEN_FILES: usize = 64;
const MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRANSFERS: usize = 128;

pub(super) struct OpenFile {
    pub(super) file: tokio::fs::File,
    pub(super) writable: bool,
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
        validate_directory(install)?;
        let transfers = install.join("transfers");
        create_directory(&transfers)?;
        let root = transfers.join(owner);
        create_directory(&root)?;
        Ok(Self {
            files: HashMap::new(),
            next_handle: 0,
            root,
            _session_slot: slot,
        })
    }

    pub(super) async fn resolve(&self, path: &str, create: bool) -> Result<PathBuf, StatusCode> {
        self.validate_roots()?;
        let relative = PathBuf::from(path);
        let parts: Vec<_> = relative.components().collect();
        if parts.len() != 1
            || parts
                .iter()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(StatusCode::PermissionDenied);
        }
        let mut candidate = self.root.clone();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(StatusCode::PermissionDenied);
            };
            candidate.push(name);
            match tokio::fs::symlink_metadata(&candidate).await {
                Ok(meta) if is_link_or_reparse(&meta) => {
                    return Err(StatusCode::PermissionDenied);
                }
                Ok(meta) => {
                    if !meta.is_file() || meta.len() > MAX_TRANSFER_BYTES {
                        return Err(StatusCode::PermissionDenied);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if meta.uid() != unsafe { libc::geteuid() }
                            || meta.nlink() != 1
                            || meta.mode() & 0o077 != 0
                        {
                            return Err(StatusCode::PermissionDenied);
                        }
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && create
                        && index + 1 == parts.len() => {}
                Err(error) => return Err(status_from_io(error)),
            }
        }
        Ok(candidate)
    }

    pub(super) async fn upload_count(&self) -> Result<usize, StatusCode> {
        self.validate_roots()?;
        let mut count = 0;
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(status_from_io)?;
        while let Some(entry) = entries.next_entry().await.map_err(status_from_io)? {
            let metadata = tokio::fs::symlink_metadata(entry.path())
                .await
                .map_err(status_from_io)?;
            if is_link_or_reparse(&metadata) || !metadata.is_file() {
                return Err(StatusCode::PermissionDenied);
            }
            count += 1;
            if count > MAX_TRANSFERS {
                return Err(StatusCode::Failure);
            }
        }
        Ok(count)
    }

    pub(super) fn validate_roots(&self) -> Result<(), StatusCode> {
        let transfers = self.root.parent().ok_or(StatusCode::PermissionDenied)?;
        let install = transfers.parent().ok_or(StatusCode::PermissionDenied)?;
        for path in [install, transfers, &self.root] {
            validate_directory(path).map_err(status_from_io)?;
        }
        Ok(())
    }

    pub(super) fn handle(&mut self) -> String {
        let h = format!("f{:016x}", self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }
}

mod handler;

fn is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    let is_link = metadata.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        is_link || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        is_link
    }
}

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

fn validate_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "transfer directory is not a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transfer directory is not owned by the Agent user",
            ));
        }
    }
    crate::ssh::validate_private_path(path)
}

fn create_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {
            #[cfg(windows)]
            set_private_acl(path, true)?;
            validate_directory(path)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => validate_directory(path),
        Err(error) => Err(error),
    }
}
