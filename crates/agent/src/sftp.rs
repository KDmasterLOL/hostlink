//! Bounded SFTP rooted in the configured Agent-owned directory.
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::path::{Component, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_WRITE_BYTES: usize = 1024 * 1024;
const MAX_OPEN_FILES: usize = 64;

pub(super) struct SftpSession {
    files: HashMap<String, tokio::fs::File>,
    next_handle: u64,
    root: PathBuf,
    _session_slot: OwnedSemaphorePermit,
}

impl SftpSession {
    pub(super) fn new(root: PathBuf, slot: OwnedSemaphorePermit) -> Self {
        Self {
            files: HashMap::new(),
            next_handle: 0,
            root,
            _session_slot: slot,
        }
    }

    async fn resolve(&self, path: &str, create: bool) -> Result<PathBuf, StatusCode> {
        let relative = PathBuf::from(path);
        let parts: Vec<_> = relative.components().collect();
        if parts.is_empty()
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
                Ok(meta) if meta.file_type().is_symlink() => {
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
        let path = self
            .resolve(&filename, flags.contains(OpenFlags::CREATE))
            .await?;
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .append(flags.contains(OpenFlags::APPEND))
            .truncate(flags.contains(OpenFlags::TRUNCATE));
        if flags.contains(OpenFlags::CREATE) {
            options
                .create(!flags.contains(OpenFlags::EXCLUDE))
                .create_new(flags.contains(OpenFlags::EXCLUDE));
        }
        let file = options.open(path).await.map_err(status_from_io)?;
        let handle = self.handle();
        self.files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }
    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let mut file = self.files.remove(&handle).ok_or(StatusCode::Failure)?;
        file.shutdown().await.map_err(status_from_io)?;
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
        f.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        let mut data = vec![0; len];
        let n = f.read(&mut data).await.map_err(status_from_io)?;
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
        f.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        f.write_all(&data).await.map_err(status_from_io)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_parent_paths_and_symlinks_outside_root() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().join("root");
        tokio::fs::create_dir(&root)
            .await
            .expect("create SFTP root");
        let outside = temp.path().join("outside");
        tokio::fs::write(&outside, b"secret")
            .await
            .expect("write outside file");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("escape")).expect("create symlink");

        let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
            .acquire_owned()
            .await
            .expect("SFTP slot");
        let session = SftpSession::new(root, permit);
        assert_eq!(
            session.resolve("../outside", false).await,
            Err(StatusCode::PermissionDenied)
        );
        #[cfg(unix)]
        assert_eq!(
            session.resolve("escape", false).await,
            Err(StatusCode::PermissionDenied)
        );
    }
}
