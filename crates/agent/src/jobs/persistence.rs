use super::database::{QUEUE, secure_sidecars, update_lock};
use super::*;
use apalis_core::{backend::TaskSink, task::builder::TaskBuilder};
use apalis_sqlite::{Config, SqliteStorage};
use sqlx::SqlitePool;

/// Apalis SQLite jobs with immutable identities and native task results.
/// Clones share one bounded pool; no filesystem JSON record backend exists.
#[derive(Debug, Clone)]
pub struct JobStore {
    pub(super) root: PathBuf,
    pub(super) pool: SqlitePool,
    backend: SqliteStorage<JobPayload>,
}

impl JobStore {
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
        let lock = update_lock(&root).await?;
        let result = async {
            let pool = database::initialize_fresh(&root).await?;
            Self::attach(root, pool).await
        }
        .await;
        // Child processes forked by other Agent tasks can temporarily inherit
        // our open descriptor before exec. Closing it alone does not release
        // flock while those inherited references survive.
        lock.unlock()?;
        result
    }

    async fn attach(root: PathBuf, pool: SqlitePool) -> io::Result<Self> {
        let backend =
            SqliteStorage::new(&pool).with_config(Config::default().queue(QUEUE).batch_size(16));
        let store = Self {
            root,
            pool,
            backend,
        };
        store.inventory().await?;
        Ok(store)
    }

    pub(crate) fn worker_backend(&self) -> SqliteStorage<JobPayload> {
        self.backend.clone()
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
        let file = open_lock(&self.root.join("runner.lock"))?;
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
    pub async fn admit(&self, id: JobId, owner: &str, spec: &JobSpec) -> io::Result<JobView> {
        validate_digest(owner)?;
        let bytes = spec.serialized()?;
        let digest = format!("{:x}", Sha256::digest(bytes));
        let lock = database::try_update_lock(&self.root)?;
        let result = async {
            database::inspect_layout(&self.root)?;
            if let Some(record) = self.find(id, owner).await? {
                if record.request_sha256 != digest || record.spec != *spec {
                    return Err(invalid("job ID already belongs to a different request"));
                }
                return Ok(record);
            }
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
                .fetch_one(&self.pool)
                .await
                .map_err(io::Error::other)?;
            if count >= MAX_JOBS as i64 {
                return Err(invalid("maximum number of jobs reached"));
            }
            let job = JobPayload {
                id,
                controller_key_sha256: owner.into(),
                request_sha256: digest,
                spec: spec.clone(),
            };
            let data = serde_json::to_vec(&job).map_err(io::Error::other)?;
            let record = JobView {
                job: job.clone(),
                state: JobState::Prepared,
                started: false,
            };
            if data.len() > MAX_RECORD_BYTES {
                return Err(invalid("durable payload exceeds maximum record size"));
            }
            let task = TaskBuilder::new(job)
                .task_id(id.to_string().parse().map_err(io::Error::other)?)
                .idempotency_key(id.to_string())
                .max_attempts(1)
                .build();
            let mut backend = self.backend.clone();
            backend.push_task(task).await.map_err(io::Error::other)?;
            // If publication of output storage fails after the commit, the Prepared
            // view stays blocking. Repeating admission cannot dispatch a process.
            fs::create_dir(self.output_dir(id))?;
            restrict_private_path(&self.output_dir(id), true)?;
            sync_directory(&self.root.join("outputs"))?;
            secure_sidecars(&self.root)?;
            Ok(record)
        }
        .await;
        // Explicit unlock before close: a concurrent child fork can briefly
        // inherit the FD until exec, so close alone can retain its flock.
        lock.unlock()?;
        result
    }

    /// Read the actual Apalis payload only for its authenticated controller.
    ///
    /// # Errors
    /// Returns permission denied for a foreign owner; rejects missing or corrupt state.
    pub async fn lookup(&self, id: JobId, owner: &str) -> io::Result<JobView> {
        self.find(id, owner)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "job not found"))
    }

    pub(super) fn output_dir(&self, id: JobId) -> PathBuf {
        self.root.join("outputs").join(id.to_string())
    }
}
