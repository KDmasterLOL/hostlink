use super::database::{connect, inspect_layout, verify_schema};
use super::*;
use std::collections::HashSet;

impl JobStore {
    pub(super) async fn inventory(&self) -> io::Result<Vec<JobView>> {
        inventory(self).await
    }
}

async fn inventory(store: &JobStore) -> io::Result<Vec<JobView>> {
    let root = &store.root;
    let pool = &store.pool;
    inspect_layout(root)?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "{} ORDER BY j.id LIMIT ?",
        super::query::ROWS
    )))
    .bind((MAX_JOBS + 1) as i64)
    .fetch_all(pool)
    .await
    .map_err(io::Error::other)?;
    if rows.len() > MAX_JOBS {
        return Err(invalid("too many durable jobs"));
    }
    let orphan_claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims c LEFT JOIN Jobs j ON c.task_id=j.id WHERE j.id IS NULL")
        .fetch_one(pool).await.map_err(io::Error::other)?;
    if orphan_claims != 0 {
        return Err(invalid("orphan started claim prevents update"));
    }
    let records = rows
        .into_iter()
        .map(|row| super::query::decode(row, None))
        .collect::<io::Result<Vec<_>>>()?;
    let ids: HashSet<_> = records.iter().map(|record| record.id).collect();
    let mut required: HashSet<_> = records
        .iter()
        .filter(|r| {
            matches!(r.state, JobState::Exited { .. }) || (r.state == JobState::Failed && r.started)
        })
        .map(|r| r.id)
        .collect();
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
        if required.remove(&id) && streams != 2 {
            return Err(invalid("terminal job lost output"));
        }
    }
    if !required.is_empty() {
        return Err(invalid("terminal job lost output directory"));
    }
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
    let root = jobs_root.to_owned();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scan_active(root))
    })
    .join()
    .map_err(|_| io::Error::other("job safety scan thread failed"))?
}

async fn scan_active(root: PathBuf) -> io::Result<Vec<String>> {
    if !inspect_layout(&root)? {
        return Err(invalid("missing jobs.db cannot prove update safety"));
    }
    let pool = connect(&root, true).await?;
    let store = JobStore::from_pool(root, pool.clone());
    let result = async {
        verify_schema(&pool).await?;
        store.inventory().await
    }
    .await;
    store.close().await;
    Ok(result?
        .into_iter()
        .filter(|r| r.state.blocks_update())
        .map(|r| r.id.to_string())
        .collect())
}
