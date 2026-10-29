use super::*;
use crate::jobs::frame::JobRequest;
use crate::jobs::protocol::handle_job_request;
use crate::jobs::protocol_tests::{fixture, start};

#[tokio::test]
async fn cancel_queued_while_update_lock_blocks_start_never_spawns() {
    let (temp, runtime, owner, spec) = fixture("printf ran > forbidden").await;
    let id = JobId::new();
    handle_job_request(start(id, &spec), &runtime, &owner)
        .await
        .unwrap();
    let update = acquire_update_lock(temp.path()).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status: String = sqlx::query_scalar("SELECT status FROM Jobs WHERE id=?")
                .bind(id.to_string())
                .fetch_one(&runtime.store.pool)
                .await
                .unwrap();
            if status == "Queued" || status == "Running" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The native Lock event may already have published Running. Retry only
    // until the worker registers its cancellation token under start_lock.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handle_job_request(JobRequest::Cancel { id }, &runtime, &owner)
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    update.unlock().unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!temp.path().join("forbidden").exists());
    assert!(!matches!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Exited { .. }
    ));
    runtime.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
