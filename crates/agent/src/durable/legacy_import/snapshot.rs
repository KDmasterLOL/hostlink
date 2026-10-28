use super::*;

const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FileDigest {
    pub len: u64,
    pub sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SourceRecord {
    pub record: JobRecord,
    pub raw: Vec<u8>,
    pub streams: [Option<FileDigest>; 2],
}

impl SourceRecord {
    pub fn mapped(&self) -> JobRecord {
        let mut record = self.record.clone();
        if record.state.blocks_update() {
            record.state = JobState::Interrupted;
        }
        record
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub records: Vec<SourceRecord>,
}

pub(super) const STREAMS: [&str; 2] = ["stdout.bin", "stderr.bin"];

impl Snapshot {
    pub fn read(root: &Path) -> io::Result<Self> {
        private_directory(root)?;
        let mut records = Vec::new();
        let mut total = 0_u64;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if records.len() >= MAX_JOBS {
                return Err(invalid("too many legacy jobs"));
            }
            let name = entry.file_name();
            let id = JobId::parse(
                name.to_str()
                    .ok_or_else(|| invalid("non-UTF8 legacy UUID"))?,
            )?;
            let dir = entry.path();
            validate_private_path(&dir, true)?;
            let mut count = 0;
            for child in fs::read_dir(&dir)? {
                let child = child?;
                count += 1;
                if count > 4
                    || !matches!(
                        child.file_name().to_str(),
                        Some("record.json" | "state.lock" | "stdout.bin" | "stderr.bin")
                    )
                {
                    return Err(invalid(
                        "unknown legacy job entry; preserve complete snapshot",
                    ));
                }
                validate_private_path(&child.path(), false)?;
                if child.file_name() == "state.lock" && fs::metadata(child.path())?.len() != 0 {
                    return Err(invalid("legacy state.lock must be empty"));
                }
            }
            let raw = read_file(&dir.join("record.json"), MAX_RECORD_BYTES as u64)?;
            let record: JobRecord = serde_json::from_slice(&raw)
                .map_err(|_| invalid("legacy record is malformed or noncanonical"))?;
            record.validate(id)?;
            // Every old transition first creates state.lock, including failed
            // launch/recovery. Its absence after Prepared means an incomplete
            // snapshot; never infer a trustworthy transitioned record from it.
            if record.state != JobState::Prepared {
                validate_private_path(&dir.join("state.lock"), false)?;
            }
            let mut streams = [None, None];
            total += raw.len() as u64;
            for (index, name) in STREAMS.iter().enumerate() {
                match fs::symlink_metadata(dir.join(name)) {
                    Ok(_) => {
                        let digest = hash_file(&dir.join(name), MAX_JOB_OUTPUT_BYTES)?;
                        total += digest.len;
                        streams[index] = Some(digest);
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            if total > MAX_SNAPSHOT_BYTES {
                return Err(invalid("legacy snapshot exceeds 512 MiB staging bound"));
            }
            if matches!(record.state, JobState::Exited { .. })
                && streams.iter().any(Option::is_none)
            {
                return Err(invalid(
                    "legacy Exited output missing; reconcile instead of inventing EOF",
                ));
            }
            let source = SourceRecord {
                record,
                raw,
                streams,
            };
            if serde_json::to_vec(&source.mapped())
                .map_err(io::Error::other)?
                .len()
                > MAX_RECORD_BYTES
            {
                return Err(invalid("mapped legacy record exceeds runtime bound"));
            }
            records.push(source);
        }
        if records.is_empty() {
            return Err(invalid("empty root is not a legacy migration snapshot"));
        }
        records.sort_by_key(|source| source.record.id.to_string());
        Ok(Self { records })
    }

    pub fn digest(&self) -> io::Result<String> {
        let mut hash = Sha256::new();
        for source in &self.records {
            hash.update(source.record.id.to_string());
            hash.update((source.raw.len() as u64).to_le_bytes());
            hash.update(&source.raw);
            let streams = serde_json::to_vec(&source.streams).map_err(io::Error::other)?;
            hash.update((streams.len() as u64).to_le_bytes());
            hash.update(streams);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}

pub(super) fn private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "snapshot/stage paths must be absolute without parent traversal",
        ));
    }
    // On Windows, canonicalize commonly adds the \\?\ verbatim prefix even
    // for ordinary C:\ paths. Do not compare those textual representations.
    // Every ancestor is independently checked for links/reparse points.
    path.canonicalize()?;
    // Reject links/reparse points in every ancestor, even when canonicalize on
    // a platform retains the original spelling of a junction.
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("linked ancestor in snapshot/stage path"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid("reparse ancestor in snapshot/stage path"));
            }
        }
    }
    validate_private_path(path, true)
}

pub(super) fn open_file(path: &Path) -> io::Result<File> {
    validate_private_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

pub(super) fn read_file(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_file(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("legacy/stage file exceeds bound"));
    }
    Ok(bytes)
}

pub(super) fn hash_file(path: &Path, limit: u64) -> io::Result<FileDigest> {
    let mut input = open_file(path)?.take(limit + 1);
    let mut hash = Sha256::new();
    let len = io::copy(&mut input, &mut hash)?;
    if len > limit {
        return Err(invalid("legacy/stage output exceeds bound"));
    }
    Ok(FileDigest {
        len,
        sha256: format!("{:x}", hash.finalize()),
    })
}

pub(super) fn write_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_output_append(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| invalid("stage file has no parent"))?,
    )
}

pub(super) fn lock_existing(path: &Path) -> io::Result<File> {
    validate_private_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    file.try_lock().map_err(|e| match e {
        fs::TryLockError::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, "offline snapshot/stage lock is held; preserve source and retry only on an offline copy"),
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(file)
}
