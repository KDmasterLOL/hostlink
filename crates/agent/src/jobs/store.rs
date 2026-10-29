use super::*;
use apalis_sqlite::{Config, SqliteStorage};
use sqlx::SqlitePool;
use std::path::PathBuf;

/// The private Apalis database associated with an Agent.
#[derive(Clone)]
pub struct JobStore {
    pub(super) pool: SqlitePool,
    pub(super) backend: SqliteStorage<CommandJob>,
}

impl JobStore {
    /// Open an existing Apalis SQLite database without migrations or creation.
    ///
    /// # Errors
    /// Fails if SQLx cannot open the existing database.
    pub async fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let pool = database::connect(&root).await?;
        Ok(Self::attach(pool))
    }

    /// Initialize the Apalis schema in a freshly enrolled Agent directory.
    ///
    /// # Errors
    /// Fails if SQLite cannot be created or Apalis migrations fail.
    pub async fn initialize_fresh(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let pool = database::initialize_fresh(&root).await?;
        Ok(Self::attach(pool))
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
