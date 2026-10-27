use super::*;

#[derive(Debug, Clone)]
pub struct JobStore {
    pub(super) root: PathBuf,
}

impl JobStore {
    /// Open only a pre-provisioned private root; never make an unsafe public root.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        validate_private_path(&root, true)?;
        let parent = root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        validate_private_path(parent, true)?;
        Ok(Self { root })
    }

    pub(crate) fn artifacts(&self, owner: &str) -> io::Result<ArtifactStore> {
        ArtifactStore::open(&self.root, owner)
    }

    /// Commit a new request before acknowledging it. Existing matching IDs never rerun.
    pub fn admit(
        &self,
        id: JobId,
        controller_key_sha256: &str,
        spec: &JobSpec,
    ) -> io::Result<Admission> {
        validate_digest(controller_key_sha256)?;
        let bytes = spec.serialized()?;
        let request_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let _update_lock = acquire_update_lock(
            self.root
                .parent()
                .ok_or_else(|| invalid("jobs root has no parent"))?,
        )?;
        let dir = self.job_dir(id);
        let missing = match fs::symlink_metadata(&dir) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        if missing {
            let mut count = 0_usize;
            for entry in fs::read_dir(&self.root)? {
                let _ = entry?;
                count = count.saturating_add(1);
                if count >= MAX_JOBS {
                    return Err(invalid("maximum number of durable jobs reached"));
                }
            }
        }
        match fs::create_dir(&dir) {
            Ok(()) => {
                restrict_private_path(&dir, true)?;
                let record = JobRecord {
                    version: SCHEMA_VERSION,
                    id,
                    controller_key_sha256: controller_key_sha256.to_owned(),
                    request_sha256,
                    spec: spec.clone(),
                    state: JobState::Prepared,
                };
                write_new_private(&dir.join("record.json"), &record)?;
                // A torn initial record must remain unusable until explicitly reconciled.
                Ok(Admission::Created(record))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let stored = self.lookup(id, controller_key_sha256)?;
                if stored.request_sha256 != request_sha256 || stored.spec != *spec {
                    return Err(invalid("job ID already belongs to a different request"));
                }
                Ok(Admission::Existing(stored))
            }
            Err(error) => Err(error),
        }
    }

    /// Look up a record only for the authenticated controller key that created it.
    pub fn lookup(&self, id: JobId, controller_key_sha256: &str) -> io::Result<JobRecord> {
        validate_digest(controller_key_sha256)?;
        let record = self.read(id)?;
        if record.controller_key_sha256 != controller_key_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job is owned by a different authenticated key",
            ));
        }
        Ok(record)
    }

    /// Persist an explicit state transition; no automatic retry of Interrupted work.
    pub fn transition(
        &self,
        id: JobId,
        controller_key_sha256: &str,
        expected: JobState,
        next: JobState,
    ) -> io::Result<JobRecord> {
        let dir = self.job_dir(id);
        validate_private_path(&dir, true)?;
        let _state_lock = exclusive_lock(&dir.join("state.lock"))?;
        let mut record = self.lookup(id, controller_key_sha256)?;
        if record.state != expected || !record.state.can_transition_to(next) {
            return Err(invalid("invalid or stale job state transition"));
        }
        record.state = next;
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        atomic_replace_private(&dir.join("record.json"), &bytes)?;
        Ok(record)
    }

    /// Recover nonterminal records left by a previous Agent process without replaying them.
    pub fn recover_nonterminal(&self) -> io::Result<()> {
        let install_root = self
            .root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        let _update_lock = acquire_update_lock(install_root)?;
        for child in fs::read_dir(&self.root)? {
            let child = child?;
            let id_name = child.file_name();
            let id = id_name
                .to_str()
                .ok_or_else(|| invalid("job directory name is not UTF-8"))
                .and_then(JobId::parse)?;
            let record = self.read(id)?;
            if matches!(record.state, JobState::Prepared | JobState::Running) {
                self.transition(
                    id,
                    &record.controller_key_sha256,
                    record.state,
                    JobState::Interrupted,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn output_path(&self, id: JobId, stream: JobOutput) -> PathBuf {
        self.job_dir(id).join(stream.file_name())
    }

    /// Read a bounded raw output slice, preserving arbitrary bytes across reconnects.
    pub(crate) fn read_output(
        &self,
        id: JobId,
        owner: &str,
        stream: JobOutput,
        offset: u64,
    ) -> io::Result<(Vec<u8>, u64, bool)> {
        let record = self.lookup(id, owner)?;
        let path = self.output_path(id, stream);
        let mut file = match read_bounded_output(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if offset != 0 {
                    return Err(invalid("output offset exceeds available bytes"));
                }
                if record.state.blocks_update() {
                    return Ok((Vec::new(), 0, false));
                }
                return Ok((Vec::new(), 0, true));
            }
            Err(error) => return Err(error),
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

    pub(super) fn job_dir(&self, id: JobId) -> PathBuf {
        self.root.join(id.to_string())
    }

    fn read(&self, id: JobId) -> io::Result<JobRecord> {
        let dir = self.job_dir(id);
        validate_private_path(&dir, true)?;
        let bytes = read_bounded_private(&dir.join("record.json"))?;
        let record: JobRecord = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("job record is invalid or incomplete"))?;
        if record.version != SCHEMA_VERSION || record.id != id {
            return Err(invalid("job record identity/version mismatch"));
        }
        validate_digest(&record.controller_key_sha256)?;
        if record.request_sha256 != format!("{:x}", Sha256::digest(record.spec.serialized()?)) {
            return Err(invalid("job record digest mismatch"));
        }
        Ok(record)
    }
}

/// Conservative updater interlock. Invalid/unknown entries fail CLOSED.
pub fn active_ids(jobs_root: &Path) -> io::Result<Vec<String>> {
    let store = JobStore::open(jobs_root)?;
    let mut active = Vec::new();
    let mut scanned = 0_usize;
    for child in fs::read_dir(&store.root)? {
        let child = child?;
        scanned += 1;
        if scanned > MAX_JOBS {
            return Err(invalid("too many job entries to prove update safety"));
        }
        let id_name = child.file_name();
        let id = id_name
            .to_str()
            .ok_or_else(|| invalid("job directory name is not UTF-8"))
            .and_then(JobId::parse)?;
        let record = store.read(id)?;
        if record.state.blocks_update() {
            active.push(id.to_string());
        }
    }
    active.sort();
    Ok(active)
}
