use hostlink_agent::jobs::{JobId, JobStore};
use std::path::Path;

/// Fault injection only: synthesize a committed claim before the simulated crash.
/// No process is launched. Production can claim only through WorkerBuilder dequeue.
pub async fn started(root: &Path, store: &JobStore, id: JobId, owner: &str) {
    let record = store.lookup(id, owner).await.unwrap();
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(root.join("jobs.db"))
            .foreign_keys(true),
    )
    .await
    .unwrap();
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("INSERT INTO StartedClaims(task_id,owner,request_sha256) VALUES(?,?,?)")
        .bind(id.to_string())
        .bind(owner)
        .bind(&record.request_sha256)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(sqlx::query("UPDATE Jobs SET status='Running',attempts=1 WHERE id=? AND status='Pending' AND attempts=0")
        .bind(id.to_string()).execute(&mut *tx).await.unwrap().rows_affected(), 1);
    tx.commit().await.unwrap();
    pool.close().await;
}
