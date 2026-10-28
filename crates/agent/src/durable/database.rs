use super::*;
use sqlx::{
    Connection, Row, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::time::Duration;

pub(super) const QUEUE: &str = "hostlink-agent-v1";
pub(super) const DATABASE: &str = "jobs.db";

/// Never wait for a filesystem lock on a Tokio executor thread: another task
/// on that executor may need to commit SQLite before releasing the same lock.
pub(super) async fn update_lock(root: &Path) -> io::Result<File> {
    let parent = root
        .parent()
        .ok_or_else(|| invalid("jobs root has no parent"))?
        .to_owned();
    tokio::task::spawn_blocking(move || acquire_update_lock(&parent))
        .await
        .map_err(io::Error::other)?
}

pub(super) fn inspect_layout(root: &Path) -> io::Result<bool> {
    validate_private_path(root, true)?;
    validate_private_path(
        root.parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?,
        true,
    )?;
    let mut database = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        match name.to_str() {
            Some(DATABASE) => {
                validate_sqlite_file(&entry.path())?;
                database = true;
            }
            Some("jobs.db-wal" | "jobs.db-shm") => validate_sidecar(&entry.path())?,
            Some("runner.lock") => validate_sqlite_file(&entry.path())?,
            Some("outputs") => validate_private_path(&entry.path(), true)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "legacy or unknown durable entry at {}; migration required: stop the old Agent, preserve the entire private jobs root and output, reconcile active/UNKNOWN operations with their controller, and use a verified importer before reusing this root; no data was removed",
                        entry.path().display()
                    ),
                ));
            }
        }
    }
    if !database
        && fs::read_dir(root)?.any(|entry| entry.map_or(true, |e| e.file_name() != "runner.lock"))
    {
        return Err(invalid(
            "durable database is missing beside existing state; preserve the root and reconcile it before migration",
        ));
    }
    Ok(database)
}

pub(super) fn validate_sqlite_file(path: &Path) -> io::Result<()> {
    validate_private_path(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(path)?.nlink() != 1 {
            return Err(invalid("durable database/lock must not be hard linked"));
        }
    }
    Ok(())
}

fn validate_sidecar(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    validate_sqlite_file(path)?;
    #[cfg(windows)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("unsafe SQLite sidecar"));
        }
        validate_windows_acl_contents(path, &metadata, false)?;
        reject_windows_hardlinks(path)?;
    }
    Ok(())
}

pub(super) fn secure_sidecars(root: &Path) -> io::Result<()> {
    validate_private_path(root, true)?;
    for name in [DATABASE, "jobs.db-wal", "jobs.db-shm"] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if name == DATABASE {
                    validate_sqlite_file(&path)?;
                } else {
                    validate_sidecar(&path)?;
                }
                // Only known regular owner/SID-validated sidecars are hardened.
                // New Windows sidecars inherit this private directory's safe ACL.
                restrict_private_path(&path, false)?;
                validate_sqlite_file(&path)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

async fn verify_connection(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let full: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(&mut *conn)
        .await?;
    let wal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&mut *conn)
        .await?;
    if full != 2 || wal != "wal" {
        return Err(sqlx::Error::Protocol(
            "durable SQLite requires WAL and synchronous FULL".into(),
        ));
    }
    Ok(())
}

pub(super) async fn connect(root: &Path, read_only: bool) -> io::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(root.join(DATABASE))
        .create_if_missing(false)
        .read_only(read_only)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    let connect_root = root.to_owned();
    let acquire_root = root.to_owned();
    SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .max_lifetime(None)
        .idle_timeout(None)
        .after_connect(move |conn, _| {
            let root = connect_root.clone();
            Box::pin(async move {
                verify_connection(conn).await?;
                secure_sidecars(&root).map_err(sqlx::Error::Io)?;
                Ok(())
            })
        })
        .before_acquire(move |conn, _| {
            let root = acquire_root.clone();
            Box::pin(async move {
                // A prior transaction may have created a new inherited Windows
                // sidecar since after_connect. Validate its owner/ACL before hardening.
                secure_sidecars(&root).map_err(sqlx::Error::Io)?;
                inspect_layout(&root).map_err(sqlx::Error::Io)?;
                verify_connection(conn).await?;
                Ok(true)
            })
        })
        .connect_with(options)
        .await
        .map_err(io::Error::other)
}

pub(super) async fn open_existing(root: &Path) -> io::Result<SqlitePool> {
    if !inspect_layout(root)? {
        return Err(invalid(
            "durable jobs.db is missing; runtime cannot initialize state. Preserve and reconcile an established root; initialize_fresh is only for a NEW private EMPTY root",
        ));
    }
    if fs::metadata(root.join(DATABASE))?.len() == 0 {
        return Err(invalid(
            "durable database is empty or torn; preserve it for reconciliation instead of initializing over it",
        ));
    }
    validate_private_path(&root.join("outputs"), true)?;
    let pool = connect(root, false).await?;
    verify_schema(&pool).await?;
    Ok(pool)
}

/// Provision only an explicitly fresh, empty private jobs root.
/// Runtime opening must never create the database or run schema migrations.
pub(super) async fn initialize_fresh(root: &Path) -> io::Result<SqlitePool> {
    inspect_layout(root)?;
    if fs::read_dir(root)?.next().transpose()?.is_some() {
        return Err(invalid(
            "fresh durable initialization requires a private EMPTY root; preserve any database, runner or output entries for reconciliation",
        ));
    }
    let path = root.join(DATABASE);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    restrict_private_path(&path, false)?;
    file.sync_all()?;
    sync_directory(root)?;
    // Set WAL only on this new empty database. Existing connections verify
    // the stored mode, so opening an incompatible database cannot convert it.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(io::Error::other)?;
    verify_connection(&mut connection)
        .await
        .map_err(io::Error::other)?;
    connection.close().await.map_err(io::Error::other)?;
    let pool = connect(root, false).await?;
    // setup() disables synchronous. Public migrations are used only for this
    // explicit provisioning; partial initialization is preserved on failure.
    apalis_sqlite::SqliteStorage::migrations()
        .run(&pool)
        .await
        .map_err(io::Error::other)?;
    sqlx::raw_sql("CREATE TABLE DurableMeta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);\nINSERT INTO DurableMeta VALUES(1,1);\nCREATE TABLE StartedClaims (job_id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES Jobs(id), owner TEXT NOT NULL, request_sha256 TEXT NOT NULL);")
        .execute(&pool).await.map_err(io::Error::other)?;
    artifacts::create_private_directory(&root.join("outputs"))?;
    secure_sidecars(root)?;
    sync_directory(root)?;
    Ok(pool)
}

pub(super) async fn verify_schema(pool: &SqlitePool) -> io::Result<()> {
    let version: i64 = sqlx::query_scalar("SELECT version FROM DurableMeta WHERE id=1")
        .fetch_one(pool).await.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("incomplete or unrecognized durable database; preserve it for reconciliation: {e}")))?;
    if version != 1 {
        return Err(invalid("unsupported durable SQLite schema version"));
    }
    // Validate the ledger read-only; never invoke Migrator::run on old state.
    let applied =
        sqlx::query("SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .map_err(io::Error::other)?;
    let migrations = apalis_sqlite::SqliteStorage::migrations();
    if applied.len() != migrations.iter().count() {
        return Err(invalid(
            "durable migration history differs from this Agent; preserve it and use an explicit verified migration",
        ));
    }
    for (row, migration) in applied.iter().zip(migrations.iter()) {
        if row.try_get::<i64, _>("version").map_err(io::Error::other)? != migration.version
            || !row
                .try_get::<bool, _>("success")
                .map_err(io::Error::other)?
            || row
                .try_get::<Vec<u8>, _>("checksum")
                .map_err(io::Error::other)?
                .as_slice()
                != migration.checksum.as_ref()
        {
            return Err(invalid(
                "durable migration version/checksum is invalid; preserve the database for reconciliation",
            ));
        }
    }
    Ok(())
}
