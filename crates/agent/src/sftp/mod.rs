//! Bounded SFTP rooted in the configured Agent-owned directory.
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::ops::Range;
use std::path::{Component, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 1024 * 1024;
const MAX_OPEN_FILES: usize = 64;
const MAX_UPLOAD_WRITE_RANGES: usize = 4096;

pub(super) struct OpenFile {
    pub(super) file: tokio::fs::File,
    pub(super) write_ranges: Vec<Range<u64>>,
    pub(super) writable: bool,
}

pub(super) struct SftpSession {
    pub(super) files: HashMap<String, OpenFile>,
    pub(super) next_handle: u64,
    pub(super) root: PathBuf,
    pub(super) sealed_root: PathBuf,
    _session_slot: OwnedSemaphorePermit,
}

impl SftpSession {
    pub(super) fn new(artifacts: crate::jobs::ArtifactStore, slot: OwnedSemaphorePermit) -> Self {
        Self {
            files: HashMap::new(),
            next_handle: 0,
            root: artifacts.upload_root(),
            sealed_root: artifacts.sealed_root(),
            _session_slot: slot,
        }
    }

    pub(super) async fn resolve(&self, path: &str, create: bool) -> Result<PathBuf, StatusCode> {
        self.validate_roots()?;
        let relative = PathBuf::from(path);
        let parts: Vec<_> = relative.components().collect();
        if parts.len() != 1
            || parts
                .iter()
                .any(|part| !matches!(part, Component::Normal(_)))
            || !path.ends_with(".upload")
            || path.len() != 71
            || !path.as_bytes()[..64]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
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
                Ok(_) => {}
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
        for directory in [&self.root, &self.sealed_root] {
            let mut entries = tokio::fs::read_dir(directory)
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
                if count > crate::jobs::MAX_ARTIFACTS_PER_CONTROLLER {
                    return Err(StatusCode::Failure);
                }
            }
        }
        Ok(count)
    }

    pub(super) fn validate_roots(&self) -> Result<(), StatusCode> {
        let owner_root = self.root.parent().ok_or(StatusCode::PermissionDenied)?;
        let artifacts_root = owner_root.parent().ok_or(StatusCode::PermissionDenied)?;
        let install_root = artifacts_root
            .parent()
            .ok_or(StatusCode::PermissionDenied)?;
        for path in [
            install_root,
            artifacts_root,
            owner_root,
            &self.root,
            &self.sealed_root,
        ] {
            crate::jobs::validate_private_path(path, true).map_err(status_from_io)?;
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
