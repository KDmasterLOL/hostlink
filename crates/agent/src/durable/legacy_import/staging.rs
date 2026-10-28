use super::*;
use apalis_core::task::builder::TaskBuilder;
use apalis_sqlite::{Config, SqliteStorage};
use futures::SinkExt;
use snapshot::{STREAMS, hash_file, open_file, write_file};
use sqlx::Row;

pub(super) async fn build(stage: &Path, source: &Path, snapshot: &Snapshot) -> io::Result<()> {
    let root = stage.join("store");
    fs::create_dir(&root)?;
    restrict_private_path(&root, true)?;
    sync_directory(stage)?;
    let pool = database::initialize_fresh(&root).await?;
    let result = async {
        // Quarantine BEFORE sending any imported task. Runtime refuses this
        // version even after a crash between sink commit and terminal sealing.
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(io::Error::other)?;
        sqlx::query("UPDATE DurableMeta SET version=? WHERE id=1")
            .bind(QUARANTINE_VERSION).execute(&mut *tx).await.map_err(io::Error::other)?;
        sqlx::raw_sql("CREATE TABLE LegacyImportSources (job_id TEXT PRIMARY KEY, record BLOB NOT NULL, record_sha256 TEXT NOT NULL, streams BLOB NOT NULL);")
            .execute(&mut *tx).await.map_err(io::Error::other)?;
        tx.commit().await.map_err(io::Error::other)?;
        let mut backend = SqliteStorage::<JobRecord>::new(&pool).with_config(
            Config::default().queue(database::QUEUE).lock_tasks(false).persist_results(false),
        );
        for original in &snapshot.records {
            let record = original.mapped();
            let id = record.id.to_string();
            let dir = root.join("outputs").join(&id);
            fs::create_dir(&dir)?;
            restrict_private_path(&dir, true)?;
            sync_directory(&root.join("outputs"))?;
            for (index, name) in STREAMS.iter().enumerate() {
                if let Some(expected) = &original.streams[index] {
                    let mut input = open_file(&source.join(&id).join(name))?.take(MAX_JOB_OUTPUT_BYTES + 1);
                    let mut output = open_output_append(&dir.join(name))?;
                    let copied = io::copy(&mut input, &mut output)?;
                    output.sync_all()?;
                    sync_directory(&dir)?;
                    if copied != expected.len || hash_file(&dir.join(name), MAX_JOB_OUTPUT_BYTES)? != *expected {
                        return Err(invalid("source output changed during copy; stage preserved"));
                    }
                }
            }
            // The real public Apalis sink owns task insertion and task IDs.
            let data = serde_json::to_vec(&record).map_err(io::Error::other)?;
            backend.send(TaskBuilder::new(data).idempotency_key(&id).max_attempts(1).build())
                .await.map_err(io::Error::other)?;
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(io::Error::other)?;
            let task_id: String = sqlx::query_scalar("SELECT id FROM Jobs WHERE job_type=? AND idempotency_key=?")
                .bind(database::QUEUE).bind(&id).fetch_one(&mut *tx).await.map_err(io::Error::other)?;
            sqlx::query("UPDATE Jobs SET status=?,attempts=1,done_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=?")
                .bind(persistence::queue_status(record.state)).bind(&task_id)
                .execute(&mut *tx).await.map_err(io::Error::other)?;
            // Only Running/Exited prove an old process reservation. Failed
            // and Interrupted are ambiguous; never invent execution history.
            if matches!(original.record.state, JobState::Running | JobState::Exited { .. }) {
                sqlx::query("INSERT INTO StartedClaims(job_id,task_id,owner,request_sha256) VALUES(?,?,?,?)")
                    .bind(&id).bind(&task_id).bind(&record.controller_key_sha256).bind(&record.request_sha256)
                    .execute(&mut *tx).await.map_err(io::Error::other)?;
            }
            // A provenance tombstone for EVERY UUID, including unstarted
            // Prepared and ambiguous Failed. Preserve the original JSON bytes.
            sqlx::query("INSERT INTO LegacyImportSources(job_id,record,record_sha256,streams) VALUES(?,?,?,?)")
                .bind(&id).bind(&original.raw).bind(format!("{:x}", Sha256::digest(&original.raw)))
                .bind(serde_json::to_vec(&original.streams).map_err(io::Error::other)?)
                .execute(&mut *tx).await.map_err(io::Error::other)?;
            tx.commit().await.map_err(io::Error::other)?;
        }
        database::secure_sidecars(&root)?;
        Ok(())
    }.await;
    pool.close().await;
    result?;
    sync_directory(&root)?;
    write_file(&stage.join("built"), snapshot.digest()?.as_bytes())
}

pub(super) async fn verify(stage: &Path, snapshot: &Snapshot) -> io::Result<()> {
    let digest = snapshot.digest()?;
    if snapshot::read_file(&stage.join("built"), 64)? != digest.as_bytes() {
        return Err(invalid(
            "stage build is incomplete; preserve it and use a separate new stage",
        ));
    }
    let root = stage.join("store");
    if !database::inspect_layout(&root)? {
        return Err(invalid("stage database missing; preserve incomplete stage"));
    }
    let pool = database::connect(&root, true).await?;
    let result = async {
        let version: i64 = sqlx::query_scalar("SELECT version FROM DurableMeta WHERE id=1")
            .fetch_one(&pool).await.map_err(io::Error::other)?;
        if version != QUARANTINE_VERSION {
            return Err(invalid("stage lost its runtime quarantine; preserve it"));
        }
        database::verify_migration_history(&pool).await?;
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&pool).await.map_err(io::Error::other)?;
        let foreign = sqlx::query("PRAGMA foreign_key_check").fetch_all(&pool).await.map_err(io::Error::other)?;
        if integrity != "ok" || !foreign.is_empty() {
            return Err(invalid("stage SQLite integrity/foreign key check failed"));
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM LegacyImportSources")
            .fetch_one(&pool).await.map_err(io::Error::other)?;
        if count != snapshot.records.len() as i64 {
            return Err(invalid("stage tombstone count mismatch"));
        }
        // Reuse the real production identity/claim/output inventory contract,
        // without lifting the schema-version quarantine imposed on runtime open.
        let store = DurableStore::attach(root.clone(), pool.clone()).await?;
        let records = store.inventory().await?;
        let expected: Vec<_> = snapshot.records.iter().map(|s| s.mapped()).collect();
        if records != expected {
            return Err(invalid("stage full record readback mismatch"));
        }
        let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims")
            .fetch_one(&pool).await.map_err(io::Error::other)?;
        let expected_claims = snapshot.records.iter().filter(|s| matches!(s.record.state, JobState::Running | JobState::Exited { .. })).count();
        if claims != expected_claims as i64 {
            return Err(invalid("stage started-claim count mismatch"));
        }
        for original in &snapshot.records {
            let id = original.record.id.to_string();
            let claimed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM StartedClaims WHERE job_id=?)")
                .bind(&id).fetch_one(&pool).await.map_err(io::Error::other)?;
            if claimed != matches!(original.record.state, JobState::Running | JobState::Exited { .. }) {
                return Err(invalid("stage started claim does not match original reservation"));
            }
            let row = sqlx::query("SELECT CASE WHEN length(record)<=65536 THEN record END AS record, CASE WHEN length(record_sha256)=64 THEN record_sha256 END AS record_sha256, CASE WHEN length(streams)<=1024 THEN streams END AS streams FROM LegacyImportSources WHERE job_id=?")
                .bind(&id).fetch_one(&pool).await.map_err(io::Error::other)?;
            if row.try_get::<Vec<u8>, _>("record").map_err(io::Error::other)? != original.raw
                || row.try_get::<String, _>("record_sha256").map_err(io::Error::other)? != format!("{:x}", Sha256::digest(&original.raw))
                || row.try_get::<Vec<u8>, _>("streams").map_err(io::Error::other)? != serde_json::to_vec(&original.streams).map_err(io::Error::other)? {
                return Err(invalid("stage original bytes/SHA/spool manifest mismatch"));
            }
            let sealed: bool = sqlx::query_scalar("SELECT attempts=1 AND max_attempts=1 AND lock_by IS NULL AND lock_at IS NULL AND done_at IS NOT NULL AND status IN ('Killed','Done','Failed') FROM Jobs WHERE job_type=? AND idempotency_key=?")
                .bind(database::QUEUE).bind(&id).fetch_one(&pool).await.map_err(io::Error::other)?;
            if !sealed {
                return Err(invalid("stage task is not sealed against dequeue/retry"));
            }
            for (index, name) in STREAMS.iter().enumerate() {
                let path = root.join("outputs").join(&id).join(name);
                match &original.streams[index] {
                    Some(expected) if hash_file(&path, MAX_JOB_OUTPUT_BYTES)? == *expected => {}
                    Some(_) => return Err(invalid("stage output bytes/SHA mismatch")),
                    None => match fs::symlink_metadata(path) {
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        _ => return Err(invalid("stage fabricated an absent legacy spool")),
                    }
                }
            }
        }
        Ok(())
    }.await;
    pool.close().await;
    result
}
