use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JobOutput {
    Stdout,
    Stderr,
}

impl JobOutput {
    pub(super) fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.bin",
            Self::Stderr => "stderr.bin",
        }
    }
}

pub(crate) fn open_output_append(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("output path has no parent"))?;
    validate_private_path(parent, true)?;
    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    restrict_private_path(path, false)?;
    sync_directory(parent)?;
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
}

pub(super) fn read_bounded_output(path: &Path) -> io::Result<File> {
    validate_private_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("output must be a regular file"));
    }
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
}

impl DurableStore {
    pub(crate) fn output_path(&self, id: JobId, stream: JobOutput) -> PathBuf {
        self.output_dir(id).join(stream.file_name())
    }

    pub(crate) async fn read_output(
        &self,
        id: JobId,
        owner: &str,
        stream: JobOutput,
        offset: u64,
    ) -> io::Result<(Vec<u8>, u64, bool)> {
        let record = self.lookup(id, owner).await?;
        // Once a process attempt was claimed, terminal failure must not
        // silently turn lost output files into successful empty EOF.
        let claimed: i64 =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM StartedClaims WHERE job_id=?)")
                .bind(id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(io::Error::other)?;
        let expects_output = matches!(record.state, JobState::Exited { .. })
            || (record.state == JobState::Failed && claimed != 0);
        let dir = self.output_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(_) => validate_private_path(&dir, true)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if expects_output {
                    return Err(invalid(
                        "terminal job output is missing; reconcile lost output",
                    ));
                }
                if offset != 0 {
                    return Err(invalid("output offset exceeds available bytes"));
                }
                return Ok((Vec::new(), 0, !record.state.blocks_update()));
            }
            Err(e) => return Err(e),
        }
        let mut file = match read_bounded_output(&self.output_path(id, stream)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if expects_output {
                    return Err(invalid(
                        "terminal job output is missing; reconcile lost output",
                    ));
                }
                if offset != 0 {
                    return Err(invalid("output offset exceeds available bytes"));
                }
                return Ok((Vec::new(), 0, !record.state.blocks_update()));
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if offset > len {
            return Err(invalid("output offset exceeds available bytes"));
        }
        use std::io::Seek;
        file.seek(io::SeekFrom::Start(offset))?;
        let mut bytes = vec![0; MAX_OUTPUT_CHUNK_BYTES.min((len - offset) as usize)];
        file.read_exact(&mut bytes)?;
        let next = offset + bytes.len() as u64;
        Ok((bytes, next, !record.state.blocks_update() && next == len))
    }
}
