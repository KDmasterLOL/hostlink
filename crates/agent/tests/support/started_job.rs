#![allow(dead_code)]

use apalis_core::{backend::TaskSink, task::builder::TaskBuilder};
use apalis_sqlite::{Config, SqliteStorage};
use hostlink_agent::jobs::CommandJob;
use sqlx::sqlite::SqliteConnectOptions;
use std::path::Path;

/// Add a task through the actual Apalis TaskSink; no HostLink jobs API.
pub async fn queued(root: &Path) -> String {
    let pool =
        sqlx::SqlitePool::connect_with(SqliteConnectOptions::new().filename(root.join("jobs.db")))
            .await
            .unwrap();
    let id = ulid::Ulid::generate().to_string();
    let task = TaskBuilder::new(CommandJob {
        program: "echo".into(),
        args: vec!["disposable".into()],
        cwd: None,
    })
    .task_id(id.parse().unwrap())
    .build();
    let mut storage =
        SqliteStorage::<CommandJob>::new(&pool).with_config(Config::default().queue("commands"));
    storage.push_task(task).await.unwrap();
    pool.close().await;
    id
}

/// Fault injection for a native Apalis Running job; never launches a child.
pub async fn started(root: &Path, id: &str) {
    let pool =
        sqlx::SqlitePool::connect_with(SqliteConnectOptions::new().filename(root.join("jobs.db")))
            .await
            .unwrap();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,layers,last_seen,started_at) VALUES('fixture-worker','commands','SqliteStorage','',0,0) ON CONFLICT(id) DO UPDATE SET last_seen=0")
        .execute(&pool).await.unwrap();
    assert_eq!(
        sqlx::query("UPDATE Jobs SET status='Running',attempts=1,lock_by='fixture-worker',lock_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=? AND status='Pending'")
            .bind(id).execute(&pool).await.unwrap().rows_affected(),
        1
    );
    pool.close().await;
}

/// Simulate a completed command for updater/service interlock fixtures only.
pub async fn completed(root: &Path, id: &str) {
    let pool =
        sqlx::SqlitePool::connect_with(SqliteConnectOptions::new().filename(root.join("jobs.db")))
            .await
            .unwrap();
    assert_eq!(
        sqlx::query("UPDATE Jobs SET status='Done',attempts=1,last_result='{\"Ok\":0}',done_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=? AND status='Pending'")
            .bind(id).execute(&pool).await.unwrap().rows_affected(),
        1
    );
    pool.close().await;
}
