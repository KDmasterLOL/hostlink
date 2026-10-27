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

struct OpenFile {
    file: tokio::fs::File,
    write_ranges: Vec<Range<u64>>,
    writable: bool,
}

pub(super) struct SftpSession {
    files: HashMap<String, OpenFile>,
    next_handle: u64,
    root: PathBuf,
    sealed_root: PathBuf,
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

    async fn resolve(&self, path: &str, create: bool) -> Result<PathBuf, StatusCode> {
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

    async fn upload_count(&self) -> Result<usize, StatusCode> {
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

    fn validate_roots(&self) -> Result<(), StatusCode> {
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

    fn handle(&mut self) -> String {
        let h = format!("f{:016x}", self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }
    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if self.files.len() >= MAX_OPEN_FILES
            || !(flags.contains(OpenFlags::READ) || flags.contains(OpenFlags::WRITE))
        {
            return Err(StatusCode::Failure);
        }
        let create = flags.contains(OpenFlags::CREATE);
        let write = flags.contains(OpenFlags::WRITE);
        if flags.contains(OpenFlags::TRUNCATE)
            || flags.contains(OpenFlags::APPEND)
            || (write && (!create || !flags.contains(OpenFlags::EXCLUDE)))
            || (create && (!write || !flags.contains(OpenFlags::EXCLUDE)))
            || (!flags.contains(OpenFlags::READ) && !write)
        {
            return Err(StatusCode::PermissionDenied);
        }
        let path = self
            .resolve(&filename, flags.contains(OpenFlags::CREATE))
            .await?;
        if create {
            if filename.len() != 71
                || !filename.ends_with(".upload")
                || !filename.as_bytes()[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            {
                return Err(StatusCode::PermissionDenied);
            }
            if self.upload_count().await? >= crate::jobs::MAX_ARTIFACTS_PER_CONTROLLER {
                return Err(StatusCode::Failure);
            }
        }
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .append(flags.contains(OpenFlags::APPEND))
            .truncate(flags.contains(OpenFlags::TRUNCATE));
        if flags.contains(OpenFlags::CREATE) {
            options.create_new(true);
            #[cfg(unix)]
            {
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
        } else {
            #[cfg(unix)]
            {
                options.custom_flags(libc::O_NOFOLLOW);
            }
        }
        let file = options.open(path).await.map_err(status_from_io)?;
        if create {
            let over_limit = match self.upload_count().await {
                Ok(count) => count > crate::jobs::MAX_ARTIFACTS_PER_CONTROLLER,
                Err(error) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(self.root.join(&filename)).await;
                    return Err(error);
                }
            };
            if over_limit {
                drop(file);
                tokio::fs::remove_file(self.root.join(&filename))
                    .await
                    .map_err(status_from_io)?;
                return Err(StatusCode::Failure);
            }
        }
        let handle = self.handle();
        self.files.insert(
            handle.clone(),
            OpenFile {
                file,
                write_ranges: Vec::new(),
                writable: write,
            },
        );
        Ok(Handle { id, handle })
    }
    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let mut file = self.files.remove(&handle).ok_or(StatusCode::Failure)?;
        file.file.shutdown().await.map_err(status_from_io)?;
        Ok(ok(id))
    }
    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let len = usize::try_from(len).map_err(|_| StatusCode::BadMessage)?;
        if len > MAX_READ_BYTES {
            return Err(StatusCode::BadMessage);
        }
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        f.file
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        let mut data = vec![0; len];
        let n = f.file.read(&mut data).await.map_err(status_from_io)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(n);
        Ok(Data { id, data })
    }
    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if data.len() > MAX_WRITE_BYTES {
            return Err(StatusCode::BadMessage);
        }
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if !f.writable {
            return Err(StatusCode::Failure);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(StatusCode::BadMessage)?;
        if end > crate::jobs::MAX_ARTIFACT_BYTES
            || f.write_ranges
                .iter()
                .any(|range| offset < range.end && range.start < end)
        {
            return Err(StatusCode::Failure);
        }
        let merged_ranges = if data.is_empty() {
            None
        } else {
            let mut ranges = f.write_ranges.clone();
            ranges.push(offset..end);
            ranges.sort_unstable_by_key(|range| range.start);
            let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
            for range in ranges {
                if let Some(previous) = merged.last_mut()
                    && range.start <= previous.end
                {
                    previous.end = previous.end.max(range.end);
                    continue;
                }
                merged.push(range);
            }
            if merged.len() > MAX_UPLOAD_WRITE_RANGES {
                return Err(StatusCode::Failure);
            }
            Some(merged)
        };
        f.file
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        f.file.write_all(&data).await.map_err(status_from_io)?;
        // Tokio's filesystem writes may still be running on a blocking thread
        // after write_all returns. SFTP WRITE success must mean the bytes are
        // visible to a separately opened handle, including for pipelined
        // out-of-order packet offsets. This is completion, not fsync durability.
        f.file.flush().await.map_err(status_from_io)?;
        if let Some(ranges) = merged_ranges {
            f.write_ranges = ranges;
        }
        Ok(ok(id))
    }
    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = tokio::fs::metadata(self.resolve(&path, false).await?)
            .await
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }
    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = tokio::fs::symlink_metadata(self.resolve(&path, false).await?)
            .await
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }
    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let m = self
            .files
            .get(&handle)
            .ok_or(StatusCode::Failure)?
            .file
            .metadata()
            .await
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }
    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(self.resolve(&filename, false).await?)
            .await
            .map_err(status_from_io)?;
        Ok(ok(id))
    }
}

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
