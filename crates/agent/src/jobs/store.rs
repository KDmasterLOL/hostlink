use super::*;
use apalis_sqlite::{Config, SqliteStorage};
use sqlx::SqlitePool;

/// The private Apalis database associated with an Agent.
#[derive(Clone)]
pub struct JobStore {
    pub(super) pool: SqlitePool,
    pub(super) backend: SqliteStorage<CommandJob>,
}

impl JobStore {
    /// Open a previously initialized v5 database without migration.
    ///
    /// # Errors
    /// Fails on missing, unsafe, corrupt or incompatible state.
    pub async fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let pool = database::open_existing(&root).await?;
        Ok(Self::attach(pool))
    }

    /// Initialize an empty private directory as a v5 database.
    ///
    /// # Errors
    /// Fails if the root is not empty and private or initialization fails.
    pub async fn initialize_fresh(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let lock = database::update_lock(&root).await?;
        let result = database::initialize_fresh(&root).await.map(Self::attach);
        lock.unlock()?;
        result
    }

    fn attach(pool: SqlitePool) -> Self {
        let backend = SqliteStorage::new(&pool).with_config(
            Config::default()
                .queue(database::QUEUE)
                .batch_size(MAX_ACTIVE_JOBS),
        );
        Self { pool, backend }
    }

    /// Close the shared SQLite pool.
    pub async fn close(self) {
        self.pool.close().await;
    }
}

/// Return IDs that may still execute, for service and updater admission.
///
/// # Errors
/// Fails closed if the private database cannot be verified or read.
pub fn active_ids(root: &Path) -> io::Result<Vec<String>> {
    let root = root.to_owned();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                if !database::inspect_layout(&root)? {
                    return Err(invalid("missing jobs database"));
                }
                let pool = database::connect(&root, true).await?;
                let result = async {
                    database::verify_schema(&pool).await?;
                    sqlx::query_scalar::<_, String>(
                        "SELECT id FROM Jobs WHERE status NOT IN ('Done','Killed') AND NOT (status='Failed' AND attempts >= max_attempts) ORDER BY id",
                    )
                    .fetch_all(&pool)
                    .await
                    .map_err(io::Error::other)
                }
                .await;
                pool.close().await;
                result
            })
    })
    .join()
    .map_err(|_| io::Error::other("job inventory thread failed"))?
}
