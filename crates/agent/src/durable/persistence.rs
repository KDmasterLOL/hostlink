use super::database::{QUEUE, inspect_layout, secure_sidecars, update_lock};
use super::*;
use apalis_core::task::builder::TaskBuilder;
use apalis_sqlite::{Config, SqliteStorage};
use futures::SinkExt;
use sqlx::{Row, SqliteConnection, SqlitePool, sqlite::SqliteRow};

/// Apalis SQLite jobs with immutable identities and one-use process claims.
/// Clones share one bounded pool; no filesystem JSON record backend exists.
#[derive(Debug, Clone)]
pub struct DurableStore {
    pub(super) root: PathBuf,
    pub(super) pool: SqlitePool,
    backend: SqliteStorage<JobRecord>,
}

impl DurableStore {
    /// Open an already provisioned private root without creating replacement state.
    ///
    /// # Errors
    /// Rejects missing databases (including empty/runner-only roots), unsafe paths,
    /// legacy state, incompatible migration history and SQLite durability failures.
    pub async fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        // Existing-state verification never admits a job or upgrades the
        // schema. A registered Windows updater holds update.lock while it
        // waits for its replacement Agent's authenticated health; acquiring
        // that lock here would deadlock the replacement startup.
        let pool = database::open_existing(&root).await?;
        Self::attach(root, pool).await
    }

    /// Explicitly provision a NEW private EMPTY jobs root for fresh installation.
    /// Never use for runtime recovery; ordinary opening cannot create a database.
    ///
    /// # Errors
    /// Rejects any existing database, runner, output or unknown entry, unsafe
    /// ownership/permissions and initialization errors. Partial state is preserved
    /// on failure and is never silently overwritten by a retry.
    pub async fn initialize_fresh(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let _lock = update_lock(&root).await?;
        let pool = database::initialize_fresh(&root).await?;
        Self::attach(root, pool).await
    }

    async fn attach(root: PathBuf, pool: SqlitePool) -> io::Result<Self> {
        let backend = SqliteStorage::new(&pool).with_config(Config::default().queue(QUEUE));
        let store = Self {
            root,
            pool,
            backend,
        };
        store.inventory_inner(true).await?;
        Ok(store)
    }

    /// Close all pooled handles before explicitly disposing a test-owned root.
    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Hold this lease for the whole Agent serving lifetime, before recovery.
    ///
    /// # Errors
    /// Fails when another live Agent owns this root or its lock is unsafe.
    pub fn acquire_runner(&self) -> io::Result<File> {
        let path = self.root.join("runner.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match fs::symlink_metadata(&path) {
            Ok(_) => database::validate_sqlite_file(&path)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let file = options.open(&path)?;
        restrict_private_path(&path, false)?;
        file.try_lock().map_err(io::Error::other)?;
        Ok(file)
    }

    pub(crate) fn artifacts(&self, owner: &str) -> io::Result<ArtifactStore> {
        ArtifactStore::open(&self.root, owner)
    }

    /// Persist via the actual Apalis task sink before reporting admission.
    ///
    /// # Errors
    /// Rejects conflicting owner/spec, unsafe/orphan state, capacity and commit errors.
    /// A failed/uncertain acknowledgement never authorizes a new process.
    pub async fn admit(&self, id: JobId, owner: &str, spec: &JobSpec) -> io::Result<Admission> {
        validate_digest(owner)?;
        let bytes = spec.serialized()?;
        let digest = format!("{:x}", Sha256::digest(bytes));
        let _lock = update_lock(&self.root).await?;
        inspect_layout(&self.root)?;
        let records = self.inventory().await?;
        if let Some(record) = records.into_iter().find(|record| record.id == id) {
            authenticate(&record, owner)?;
            if record.request_sha256 != digest || record.spec != *spec {
                return Err(invalid("job ID already belongs to a different request"));
            }
            return Ok(Admission::Existing(record));
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
            .fetch_one(&self.pool)
            .await
            .map_err(io::Error::other)?;
        if count >= MAX_JOBS as i64 {
            return Err(invalid("maximum number of durable jobs reached"));
        }
        let record = JobRecord {
            version: SCHEMA_VERSION,
            id,
            controller_key_sha256: owner.into(),
            request_sha256: digest,
            spec: spec.clone(),
            state: JobState::Prepared,
        };
        // Reserve the largest lifecycle representation before committing an ID.
        // Otherwise a valid admission could become impossible to finish/recover.
        let mut largest = record.clone();
        largest.state = JobState::Exited { code: i32::MIN };
        if serde_json::to_vec(&largest)
            .map_err(io::Error::other)?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err(invalid(
                "durable payload leaves no room for its terminal state",
            ));
        }
        let data = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if data.len() > MAX_RECORD_BYTES {
            return Err(invalid("durable payload exceeds maximum record size"));
        }
        let task = TaskBuilder::new(data)
            .idempotency_key(id.to_string())
            .max_attempts(1)
            .build();
        let mut backend = self.backend.clone();
        backend.send(task).await.map_err(io::Error::other)?;
        let actual = self.lookup(id, owner).await?;
        if actual != record {
            return Err(invalid("Apalis admission readback mismatch"));
        }
        // If publication of output storage fails after the commit, the Prepared
        // record stays blocking. A retry only returns Existing; it cannot execute.
        fs::create_dir(self.output_dir(id))?;
        restrict_private_path(&self.output_dir(id), true)?;
        sync_directory(&self.root.join("outputs"))?;
        secure_sidecars(&self.root)?;
        Ok(Admission::Created(record))
    }

    /// Read the actual Apalis payload only for its authenticated controller.
    ///
    /// # Errors
    /// Returns permission denied for a foreign owner; rejects missing or corrupt state.
    pub async fn lookup(&self, id: JobId, owner: &str) -> io::Result<JobRecord> {
        validate_digest(owner)?;
        let mut conn = self.pool.acquire().await.map_err(io::Error::other)?;
        let (record, _) = read_record(&mut conn, id, false).await?;
        authenticate(&record, owner)?;
        Ok(record)
    }

    pub(super) fn output_dir(&self, id: JobId) -> PathBuf {
        self.root.join("outputs").join(id.to_string())
    }
}

pub(super) fn authenticate(record: &JobRecord, owner: &str) -> io::Result<()> {
    if record.controller_key_sha256 != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "job is owned by a different authenticated key",
        ));
    }
    Ok(())
}

pub(super) fn queue_status(state: JobState) -> &'static str {
    match state {
        JobState::Prepared => "Pending",
        JobState::Running => "Running",
        JobState::Exited { .. } => "Done",
        JobState::Failed => "Failed",
        JobState::Interrupted => "Killed",
    }
}

pub(super) fn decode(
    row: &SqliteRow,
    id: JobId,
    allow_orphan: bool,
) -> io::Result<(JobRecord, String)> {
    let data: &[u8] = row.try_get("job").map_err(io::Error::other)?;
    if data.len() > MAX_RECORD_BYTES {
        return Err(invalid("durable payload exceeds maximum record size"));
    }
    let record: JobRecord = serde_json::from_slice(data).map_err(io::Error::other)?;
    record.validate(id)?;
    let task_id: String = row.try_get("id").map_err(io::Error::other)?;
    let status: String = row.try_get("status").map_err(io::Error::other)?;
    let queue: String = row.try_get("job_type").map_err(io::Error::other)?;
    let max_attempts: i64 = row.try_get("max_attempts").map_err(io::Error::other)?;
    if queue != QUEUE
        || max_attempts != 1
        || (status != queue_status(record.state)
            && !(allow_orphan && record.state == JobState::Running && status == "Pending"))
    {
        return Err(invalid(
            "Apalis queue/payload state mismatch; operation is UNKNOWN",
        ));
    }
    Ok((record, task_id))
}

pub(super) async fn read_record(
    conn: &mut SqliteConnection,
    id: JobId,
    allow_orphan: bool,
) -> io::Result<(JobRecord, String)> {
    let row = sqlx::query("SELECT CASE WHEN length(job)<=? THEN job ELSE NULL END AS job,id,job_type,status,max_attempts FROM Jobs WHERE job_type=? AND idempotency_key=?")
        .bind(MAX_RECORD_BYTES as i64)
        .bind(QUEUE)
        .bind(id.to_string())
        .fetch_optional(&mut *conn)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "durable job not found"))?;
    let (record, task_id) = decode(&row, id, allow_orphan)?;
    let claim =
        sqlx::query("SELECT task_id,owner,request_sha256 FROM StartedClaims WHERE job_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *conn)
            .await
            .map_err(io::Error::other)?;
    if let Some(claim) = &claim
        && (claim
            .try_get::<String, _>("task_id")
            .map_err(io::Error::other)?
            != task_id
            || claim
                .try_get::<String, _>("owner")
                .map_err(io::Error::other)?
                != record.controller_key_sha256
            || claim
                .try_get::<String, _>("request_sha256")
                .map_err(io::Error::other)?
                != record.request_sha256)
    {
        return Err(invalid(
            "started claim identity does not match immutable Apalis task",
        ));
    }
    if (record.state == JobState::Prepared && claim.is_some())
        || (matches!(record.state, JobState::Running | JobState::Exited { .. }) && claim.is_none())
    {
        return Err(invalid("durable lifecycle/started claim mismatch"));
    }
    Ok((record, task_id))
}
