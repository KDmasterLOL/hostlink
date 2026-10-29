use super::*;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::time::Duration;

pub(super) const QUEUE: &str = "commands";
const DATABASE: &str = "jobs.db";

// SQLx owns SQLite connections; Apalis owns the schema and job records.
// An existing store must not be silently replaced by an empty database.
pub(super) async fn connect(root: &Path) -> io::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(root.join(DATABASE))
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(io::Error::other)
}

// Called only for the freshly enrolled Agent; never when starting an existing one.
pub(super) async fn initialize_fresh(root: &Path) -> io::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(root.join(DATABASE))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(io::Error::other)?;
    if let Err(error) = apalis_sqlite::SqliteStorage::migrations().run(&pool).await {
        pool.close().await;
        return Err(io::Error::other(error));
    }
    Ok(pool)
}
