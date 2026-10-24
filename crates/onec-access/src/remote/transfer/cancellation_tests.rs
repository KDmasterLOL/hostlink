use super::{RemoteStagingGuard, create_local_temp_file, download::transfer_temp_path};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unique_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hostlink-transfer-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[tokio::test]
async fn cancelling_after_local_temp_creation_schedules_file_cleanup() {
    let path = unique_path("local-cancel");
    let task_path = path.clone();
    let task = tokio::spawn(async move {
        let (_guard, _file) = create_local_temp_file(task_path).expect("create staged file");
        std::future::pending::<()>().await;
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("staged file was created");
    task.abort();
    let _ = task.await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while path.exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("cancelled transfer removes its local staged file");
}

#[tokio::test]
async fn cancelling_partial_download_removes_staging_without_publishing_target() {
    use tokio::io::AsyncWriteExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let target = directory.path().join("download.bin");
    let staging = transfer_temp_path(&target);
    let task_staging = staging.clone();
    let (partial, wait_partial) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (_guard, mut file) = create_local_temp_file(task_staging).expect("create staged file");
        file.write_all(b"partial transfer")
            .await
            .expect("write partial bytes");
        let _ = partial.send(());
        std::future::pending::<()>().await;
    });

    wait_partial.await.expect("partial download staged");
    assert!(staging.exists());
    assert!(!target.exists());
    task.abort();
    let _ = task.await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while staging.exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("cancelled download removes its partial staging file");
    assert!(!target.exists(), "partial bytes are never published");
}

#[tokio::test]
async fn cancelling_upload_schedules_owned_remote_cleanup() {
    let cleaned = Arc::new(AtomicBool::new(false));
    let task_cleaned = Arc::clone(&cleaned);
    let (created, wait_created) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = RemoteStagingGuard::new(move || {
            Box::pin(async move {
                task_cleaned.store(true, Ordering::SeqCst);
            })
        });
        let _ = created.send(());
        std::future::pending::<()>().await;
    });

    wait_created.await.expect("guard created");
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !cleaned.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled upload runs its remote cleanup action");
}

#[tokio::test]
async fn cancelling_upload_with_stalled_cleanup_leaves_remote_state_unconfirmed() {
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let cleanup_confirmed = Arc::new(AtomicBool::new(false));
    let task_started = Arc::clone(&cleanup_started);
    let task_confirmed = Arc::clone(&cleanup_confirmed);
    let (created, wait_created) = tokio::sync::oneshot::channel();
    let owner = tokio::spawn(async move {
        let _guard = RemoteStagingGuard::new(move || {
            Box::pin(async move {
                task_started.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
                task_confirmed.store(true, Ordering::SeqCst);
            })
        });
        let _ = created.send(());
        std::future::pending::<()>().await;
    });

    wait_created.await.expect("guard created");
    owner.abort();
    let _ = owner.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !cleanup_started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup was attempted after cancellation");
    assert!(
        !cleanup_confirmed.load(Ordering::SeqCst),
        "a stalled remote cleanup must never be inferred as confirmed"
    );
}
