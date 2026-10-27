use super::database::{connect, inspect_layout, verify_schema};
use super::persistence::read_record;
use super::*;
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;

impl DurableStore {
    pub(super) async fn inventory(&self) -> io::Result<Vec<JobRecord>> {
        self.inventory_inner(false).await
    }
    pub(super) async fn inventory_inner(&self, allow_orphan: bool) -> io::Result<Vec<JobRecord>> {
        inventory(&self.root, &self.pool, allow_orphan).await
    }
}

async fn inventory(
    root: &Path,
    pool: &SqlitePool,
    allow_orphan: bool,
) -> io::Result<Vec<JobRecord>> {
    inspect_layout(root)?;
    let mut tx = pool.begin().await.map_err(io::Error::other)?;
    let keys = sqlx::query("SELECT idempotency_key,job_type FROM Jobs LIMIT ?")
        .bind((MAX_JOBS + 1) as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(io::Error::other)?;
    if keys.len() > MAX_JOBS {
        return Err(invalid("too many durable records to prove update safety"));
    }
    let orphan_claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims c LEFT JOIN Jobs j ON c.task_id=j.id WHERE j.id IS NULL OR c.job_id!=j.idempotency_key OR j.job_type!='hostlink-agent-v1'")
        .fetch_one(&mut *tx).await.map_err(io::Error::other)?;
    if orphan_claims != 0 {
        return Err(invalid("orphan started claim prevents update"));
    }
    let mut records = Vec::with_capacity(keys.len());
    for key in keys {
        if key
            .try_get::<String, _>("job_type")
            .map_err(io::Error::other)?
            != database::QUEUE
        {
            return Err(invalid("unknown Apalis queue in durable Agent database"));
        }
        let id = JobId::parse(
            &key.try_get::<String, _>("idempotency_key")
                .map_err(io::Error::other)?,
        )?;
        let (record, _) = read_record(&mut tx, id, allow_orphan).await?;
        records.push(record);
    }
    tx.commit().await.map_err(io::Error::other)?;
    let ids: HashSet<_> = records.iter().map(|record| record.id).collect();
    let outputs = root.join("outputs");
    validate_private_path(&outputs, true)?;
    let mut count = 0;
    for entry in fs::read_dir(outputs)? {
        let entry = entry?;
        count += 1;
        if count > MAX_JOBS {
            return Err(invalid("too many output directories"));
        }
        let name = entry.file_name();
        let id = JobId::parse(
            name.to_str()
                .ok_or_else(|| invalid("non-UTF8 output directory"))?,
        )?;
        if !ids.contains(&id) {
            return Err(invalid("orphan output directory requires reconciliation"));
        }
        validate_private_path(&entry.path(), true)?;
        let mut streams = 0;
        for output in fs::read_dir(entry.path())? {
            let output = output?;
            streams += 1;
            if streams > 2
                || !matches!(
                    output.file_name().to_str(),
                    Some("stdout.bin" | "stderr.bin")
                )
            {
                return Err(invalid("unknown durable output entry"));
            }
            read_bounded_output(&output.path())?;
        }
    }
    for record in &records {
        if matches!(record.state, JobState::Exited { .. }) {
            let dir = root.join("outputs").join(record.id.to_string());
            validate_private_path(&dir, true)?;
            read_bounded_output(&dir.join("stdout.bin"))?;
            read_bounded_output(&dir.join("stderr.bin"))?;
        }
    }
    records.sort_by_key(|record| record.id.to_string());
    Ok(records)
}

/// Conservative synchronous safety scan for service and updater entrypoints.
/// Unknown/legacy/corrupt state is an error; Interrupted is always blocking.
///
/// # Errors
/// Returns path, legacy migration, database, identity and output validation errors.
/// This does not take update.lock: the updater already holds it. It uses a
/// read-only SQLite connection and never initializes a database around old state.
pub fn active_ids(jobs_root: &Path) -> io::Result<Vec<String>> {
    if !inspect_layout(jobs_root)? {
        // A missing database cannot prove that no job was running. A removed
        // or lost database must never authorize an Agent update or service
        // replacement as though the installation were empty.
        return Err(invalid(
            "durable jobs.db is missing; initialize or reconcile the store before updating",
        ));
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        let pool = connect(jobs_root, true).await?;
                        let result = async {
                            verify_schema(&pool).await?;
                            Ok(inventory(jobs_root, &pool, false)
                                .await?
                                .into_iter()
                                .filter(|record| record.state.blocks_update())
                                .map(|record| record.id.to_string())
                                .collect())
                        }
                        .await;
                        pool.close().await;
                        result
                    })
            })
            .join()
            .map_err(|_| io::Error::other("durable safety scan thread failed"))?
    })
}
