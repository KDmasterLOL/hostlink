//! Isolated Apalis 1.0 SQLite integration experiment.
//! This deliberately does not modify or invoke the installed HostLink Agent.

use std::path::Path;

use apalis_core::{
    backend::WorkerFilter,
    task::{builder::TaskBuilder, task_id::TaskId},
};
use apalis_sqlite::{Config, SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteStorage};
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    sqlite::{SqliteJournalMode, SqliteSynchronous},
};
use uuid::Uuid;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

const QUEUE: &str = "hostlink-agent";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub program: String,
    pub args: Vec<String>,
    pub source_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub id: String,
    pub owner: String,
    pub request_sha256: String,
    pub spec: JobSpec,
}

impl JobRecord {
    pub fn new(id: Uuid, owner: &str, spec: JobSpec) -> Result<Self> {
        let request_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&spec)?));
        Ok(Self {
            id: id.to_string(),
            owner: owner.into(),
            request_sha256,
            spec,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Created,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredJob {
    pub task_id: String,
    pub status: String,
    pub attempts: i64,
    pub max_attempts: i64,
    pub record: JobRecord,
}

pub struct ApalisJobStore {
    pool: SqlitePool,
    backend: SqliteStorage<JobRecord>,
}

impl ApalisJobStore {
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        // Apalis setup sets synchronous=OFF; a single connection is required
        // for this PoC to restore and prove the durability setting.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        SqliteStorage::setup(&pool).await?;
        sqlx::query("PRAGMA synchronous=FULL")
            .execute(&pool)
            .await?;
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await?;
        if synchronous != 2 {
            return Err("Apalis SQLite connection is not in FULL synchronous mode".into());
        }
        let backend = SqliteStorage::new(&pool).with_config(Config::default().queue(QUEUE));
        Ok(Self { pool, backend })
    }

    pub async fn admit(&mut self, record: &JobRecord) -> Result<Admission> {
        if Uuid::parse_str(&record.id)?.to_string() != record.id
            || record.owner.len() != 64
            || record.spec.program.is_empty()
            || record.spec.source_sha256.len() != 64
            || format!("{:x}", Sha256::digest(serde_json::to_vec(&record.spec)?))
                != record.request_sha256
        {
            return Err("invalid source-bound JobRecord".into());
        }
        let apalis_id = TaskId::from_ulid(ulid::Ulid::generate());
        let assigned_id = apalis_id.to_string();
        let data = serde_json::to_vec(record)?;
        let task = TaskBuilder::new(data)
            .task_id(apalis_id)
            .idempotency_key(record.id.clone())
            .max_attempts(1)
            .build();
        self.backend.send(task).await?;
        let actual = self.get(&record.id).await?.ok_or("lost admitted record")?;
        if actual.record != *record {
            return Err("same JobId submitted with conflicting command or owner".into());
        }
        Ok(if actual.task_id == assigned_id {
            Admission::Created
        } else {
            Admission::Existing
        })
    }

    pub async fn get(&self, uuid: &str) -> Result<Option<StoredJob>> {
        let row = sqlx::query(
            "SELECT id, status, attempts, max_attempts, job \
             FROM Jobs WHERE job_type=? AND idempotency_key=?",
        )
        .bind(QUEUE)
        .bind(uuid)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| -> Result<StoredJob> {
            Ok(StoredJob {
                task_id: row.try_get("id")?,
                status: row.try_get("status")?,
                attempts: row.try_get("attempts")?,
                max_attempts: row.try_get("max_attempts")?,
                record: serde_json::from_slice(row.try_get("job")?)?,
            })
        })
        .transpose()
    }

    /// Exercise the *actual* Apalis orphan-recovery SQL, without executing
    /// any external command or starting an Agent worker.
    pub async fn orphan_recovery_probe(&self, uuid: &str) -> Result<(u64, StoredJob)> {
        sqlx::query(
            "INSERT INTO Workers(id,worker_type,storage_name,last_seen) \
             VALUES ('crashed-worker', ?, 'SqliteStorage', 0)",
        )
        .bind(QUEUE)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE Jobs SET status='Running',lock_by='crashed-worker',attempts=1 \
             WHERE job_type=? AND idempotency_key=?",
        )
        .bind(QUEUE)
        .bind(uuid)
        .execute(&self.pool)
        .await?;

        let affected =
            apalis_sqlite::queries::reenqueue_orphaned(&self.pool, 1, QUEUE, &WorkerFilter::None)
                .await?;
        Ok((affected, self.get(uuid).await?.ok_or("job disappeared")?))
    }

    /// A minimal persistent execution claim required by HostLink to avoid
    /// an unsafe replay after an Apalis worker re-enqueues an orphaned job.
    /// This is custom SQL, not provided by Apalis.
    pub async fn claim_at_most_once(&self, uuid: &str) -> Result<bool> {
        sqlx::query("CREATE TABLE IF NOT EXISTS StartedClaims (job_id TEXT PRIMARY KEY)")
            .execute(&self.pool)
            .await?;
        let claimed =
            sqlx::query("INSERT INTO StartedClaims(job_id) VALUES (?) ON CONFLICT DO NOTHING")
                .bind(uuid)
                .execute(&self.pool)
                .await?;
        Ok(claimed.rows_affected() == 1)
    }

    pub async fn durable_mode(&self) -> Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>("PRAGMA synchronous")
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn queue_rows(&self) -> Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM Jobs")
            .fetch_one(&self.pool)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(command: &str) -> JobSpec {
        JobSpec {
            program: command.into(),
            args: vec!["--version".into()],
            source_sha256: "a".repeat(64),
        }
    }

    #[tokio::test]
    async fn same_id_and_command_are_idempotent_but_different_command_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApalisJobStore::open(&dir.path().join("jobs.db"))
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let owner = "b".repeat(64);
        let first = JobRecord::new(id, &owner, spec("program-one")).unwrap();
        assert_eq!(store.admit(&first).await.unwrap(), Admission::Created);
        assert_eq!(store.admit(&first).await.unwrap(), Admission::Existing);
        let different = JobRecord::new(id, &owner, spec("program-two")).unwrap();
        assert!(store.admit(&different).await.is_err());
        assert_eq!(store.queue_rows().await.unwrap(), 1);
        assert_eq!(
            store.get(&id.to_string()).await.unwrap().unwrap().record,
            first
        );
    }

    #[tokio::test]
    async fn job_is_durable_across_reopen_and_full_sync_mode_is_restored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.db");
        let id = Uuid::new_v4();
        let record = JobRecord::new(id, &"b".repeat(64), spec("program")).unwrap();
        {
            let mut store = ApalisJobStore::open(&path).await.unwrap();
            assert_eq!(store.durable_mode().await.unwrap(), 2);
            assert_eq!(store.admit(&record).await.unwrap(), Admission::Created);
        }
        let store = ApalisJobStore::open(&path).await.unwrap();
        assert_eq!(
            store.get(&id.to_string()).await.unwrap().unwrap().record,
            record
        );
        assert_eq!(store.durable_mode().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn apalis_orphan_recovery_makes_exhausted_job_pending_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApalisJobStore::open(&dir.path().join("jobs.db"))
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let record = JobRecord::new(id, &"b".repeat(64), spec("program")).unwrap();
        store.admit(&record).await.unwrap();
        let (affected, recovered) = store.orphan_recovery_probe(&id.to_string()).await.unwrap();
        assert_eq!(affected, 1);
        assert_eq!(recovered.status, "Pending");
        assert_eq!(recovered.max_attempts, 1);
        assert_eq!(recovered.attempts, 2);
        // Apalis fetch_next.sql accepts Pending regardless of attempts/max_attempts.
    }

    #[tokio::test]
    async fn independent_claim_prevents_reexecution_after_orphan_requeue() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApalisJobStore::open(&dir.path().join("jobs.db"))
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let record = JobRecord::new(id, &"b".repeat(64), spec("program")).unwrap();
        store.admit(&record).await.unwrap();
        assert!(store.claim_at_most_once(&record.id).await.unwrap());
        store.orphan_recovery_probe(&record.id).await.unwrap();
        assert!(!store.claim_at_most_once(&record.id).await.unwrap());
        drop(store);
        let store = ApalisJobStore::open(&dir.path().join("jobs.db"))
            .await
            .unwrap();
        assert!(!store.claim_at_most_once(&record.id).await.unwrap());
    }

    #[tokio::test]
    async fn concurrent_identical_submissions_admit_one_job() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jobs.db");
        let mut first = ApalisJobStore::open(&path).await.unwrap();
        let mut second = ApalisJobStore::open(&path).await.unwrap();
        let record = JobRecord::new(Uuid::new_v4(), &"b".repeat(64), spec("program")).unwrap();
        let (a, b) = tokio::join!(first.admit(&record), second.admit(&record));
        assert!(matches!(
            (a.unwrap(), b.unwrap()),
            (Admission::Created, Admission::Existing) | (Admission::Existing, Admission::Created)
        ));
        assert_eq!(first.queue_rows().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn owner_mismatch_and_tampered_digest_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ApalisJobStore::open(&dir.path().join("jobs.db"))
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let original = JobRecord::new(id, &"b".repeat(64), spec("program")).unwrap();
        store.admit(&original).await.unwrap();

        let wrong_owner = JobRecord::new(id, &"c".repeat(64), spec("program")).unwrap();
        // The underlying Apalis backend silently ignores a changed payload
        // for the same idempotency key, requiring the additional read/compare.
        let raw_task = TaskBuilder::new(serde_json::to_vec(&wrong_owner).unwrap())
            .idempotency_key(wrong_owner.id.clone())
            .max_attempts(1)
            .build();
        store.backend.send(raw_task).await.unwrap();
        assert!(store.admit(&wrong_owner).await.is_err());

        let mut forged = original.clone();
        forged.request_sha256 = "0".repeat(64);
        assert!(store.admit(&forged).await.is_err());
        assert_eq!(
            store.get(&id.to_string()).await.unwrap().unwrap().record,
            original
        );
    }
}
