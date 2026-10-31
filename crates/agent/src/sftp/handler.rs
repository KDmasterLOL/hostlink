use super::*;

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
        if create && self.upload_count().await? >= MAX_TRANSFERS {
            return Err(StatusCode::Failure);
        }
        let directory = self.private_directory()?;
        let file = directory
            .open_file_with(
                path.file_name().ok_or(StatusCode::PermissionDenied)?,
                OpenOptions {
                    access: if write {
                        FileAccess::ReadWrite
                    } else {
                        FileAccess::Read
                    },
                    creation: if create {
                        FileCreation::CreateNew
                    } else {
                        FileCreation::Existing
                    },
                    ..OpenOptions::default()
                },
            )
            .map_err(status_from_private)?;
        let file = tokio::fs::File::from_std(file.try_clone_std().map_err(status_from_io)?);
        if create {
            let over_limit = match self.upload_count().await {
                Ok(count) => count > MAX_TRANSFERS,
                Err(error) => {
                    drop(file);
                    directory
                        .remove_file(&filename, Durability::None)
                        .map_err(status_from_private)?;
                    return Err(error);
                }
            };
            if over_limit {
                drop(file);
                directory
                    .remove_file(&filename, Durability::None)
                    .map_err(status_from_private)?;
                return Err(StatusCode::Failure);
            }
        }
        let handle = self.handle();
        self.files.insert(
            handle.clone(),
            OpenFile {
                file,
                writable: write,
                readable: flags.contains(OpenFlags::READ),
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
        if !f.readable {
            return Err(StatusCode::Failure);
        }
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
        if end > MAX_TRANSFER_BYTES {
            return Err(StatusCode::Failure);
        }
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
        Ok(ok(id))
    }
    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.resolve(&path, false).await?;
        let file = self
            .private_directory()?
            .open_file(path.file_name().ok_or(StatusCode::PermissionDenied)?)
            .map_err(status_from_private)?;
        let m = file
            .try_clone_std()
            .and_then(|file| file.metadata())
            .map_err(status_from_io)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }
    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
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
        self.resolve(&filename, false).await?;
        self.private_directory()?
            .remove_file(&filename, Durability::None)
            .map_err(status_from_private)?;
        Ok(ok(id))
    }
}
