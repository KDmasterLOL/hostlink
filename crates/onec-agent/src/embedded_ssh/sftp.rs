use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

const MAX_READ_BYTES: usize = 1024 * 1024;
pub(super) const MAX_OPEN_FILES: usize = 64;

pub(super) struct SftpSession {
    files: HashMap<String, tokio::fs::File>,
    next_handle: u64,
    _session_slot: OwnedSemaphorePermit,
}

impl SftpSession {
    pub(super) fn new(session_slot: OwnedSemaphorePermit) -> Self {
        Self {
            files: HashMap::new(),
            next_handle: 0,
            _session_slot: session_slot,
        }
    }

    fn allocate_handle(&mut self) -> String {
        let handle = format!("f{:016x}", self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        handle
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
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if self.files.len() >= MAX_OPEN_FILES {
            return Err(StatusCode::Failure);
        }
        let mut options = tokio::fs::OpenOptions::new();
        options
            .read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE));

        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                options.create_new(true);
            } else {
                options.create(true);
            }
        }

        let file = options
            .open(PathBuf::from(filename))
            .await
            .map_err(status_from_io)?;
        let handle = self.allocate_handle();
        self.files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let mut file = self.files.remove(&handle).ok_or(StatusCode::Failure)?;
        file.shutdown().await.map_err(status_from_io)?;
        Ok(ok_status(id))
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
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        let mut data = vec![0_u8; len];
        let read = file.read(&mut data).await.map_err(status_from_io)?;
        if read == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(read);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(status_from_io)?;
        file.write_all(&data).await.map_err(status_from_io)?;
        Ok(ok_status(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let metadata = tokio::fs::metadata(PathBuf::from(path))
            .await
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let metadata = tokio::fs::symlink_metadata(PathBuf::from(path))
            .await
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let file = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let metadata = file.metadata().await.map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&metadata),
        })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(PathBuf::from(filename))
            .await
            .map_err(status_from_io)?;
        Ok(ok_status(id))
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_owned(),
        language_tag: "en-US".to_owned(),
    }
}

fn status_from_io(error: io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StatusCode::BadMessage,
        _ => StatusCode::Failure,
    }
}
