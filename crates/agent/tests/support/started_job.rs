use hostlink_agent::jobs::{JobId, JobStore};
use std::path::Path;

/// Test-only crash injection: persist a stale native Apalis worker and a
/// Running job so normal Apalis registration can reclaim/replay it on restart.
/// No child is launched and no custom claim ledger is involved.
pub async fn started(root: &Path, store: &JobStore, id: JobId, owner: &str) {
    store.lookup(id, owner).await.unwrap();
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(root.join("jobs.db"))
            .foreign_keys(true),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,layers,last_seen,started_at) VALUES('hostlink-agent-worker','hostlink-agent','SqliteStorage','',0,0) ON CONFLICT(id) DO UPDATE SET last_seen=0")
        .execute(&pool).await.unwrap();
    assert_eq!(sqlx::query("UPDATE Jobs SET status='Running',attempts=1,lock_by='hostlink-agent-worker',lock_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=? AND status='Pending' AND attempts=0")
        .bind(id.to_string()).execute(&pool).await.unwrap().rows_affected(), 1);
    pool.close().await;
}
