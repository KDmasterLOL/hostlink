use super::protocol_tests::fixture;
use super::*;

async fn stop(worker: &mut JobWorker, runtime: &JobRuntime) {
    runtime.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn wait_state(runtime: &JobRuntime, id: JobId, owner: &str, expected: JobState) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.store.lookup(id, owner).await.unwrap().state != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_result_is_authoritative_and_payload_never_contains_lifecycle() {
    let (_temp, runtime, owner, spec) = fixture("exit 7").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    let backend = runtime.store.worker_backend();
    let payload: Vec<u8> = sqlx::query_scalar("SELECT job FROM Jobs")
        .fetch_one(backend.pool())
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(json.get("state").is_none());
    assert!(json.get("version").is_none());
    if !super::process_tests::native_containment_available() {
        return;
    }
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, id, &owner, JobState::Exited { code: 7 }).await;
    let (after, status, result, attempts): (Vec<u8>, String, String, i64) =
        sqlx::query_as("SELECT job,status,last_result,attempts FROM Jobs")
            .fetch_one(backend.pool())
            .await
            .unwrap();
    assert_eq!(after, payload);
    assert_eq!(status, "Done");
    assert_eq!(
        serde_json::from_str::<Result<i32, String>>(&result).unwrap(),
        Ok(7)
    );
    assert_eq!(attempts, 1);
    assert_eq!(
        runtime.store.list(&owner, 1, Some("Done")).await.unwrap()[0].id,
        id
    );
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn ordinary_source_failure_is_persisted_and_worker_continues() {
    let (_temp, runtime, owner, spec) = fixture("exit 0").await;
    let first = JobId::new();
    let second = JobId::new();
    runtime.store.admit(first, &owner, &spec).await.unwrap();
    runtime.store.admit(second, &owner, &spec).await.unwrap();
    std::fs::remove_file(&spec.program).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, first, &owner, JobState::Failed).await;
    wait_state(&runtime, second, &owner, JobState::Failed).await;
    assert!(runtime.accepting.load(Ordering::Acquire));
    for id in [first, second] {
        let result: String = sqlx::query_scalar("SELECT last_result FROM Jobs WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&runtime.store.pool)
            .await
            .unwrap();
        assert!(
            serde_json::from_str::<Result<i32, String>>(&result)
                .unwrap()
                .is_err()
        );
    }
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn native_orphan_requeue_can_run_again_with_existing_output() {
    if !super::process_tests::native_containment_available() {
        return;
    }
    use apalis_core::backend::WorkerFilter;
    let (temp, runtime, owner, spec) = fixture("printf x >> counter; printf replay").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    // Simulate persisted evidence of an earlier execution and its crashed worker.
    std::fs::write(temp.path().join("counter"), b"x").unwrap();
    let output = runtime.store.output_path(id, JobOutput::Stdout);
    drop(open_output_append(&output).unwrap());
    std::fs::write(&output, b"first").unwrap();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,last_seen) VALUES('crashed','hostlink-agent','SqliteStorage',0)")
        .execute(&runtime.store.pool).await.unwrap();
    apalis_sqlite::queries::lock_tasks(&runtime.store.pool, &[id.to_string()], "crashed")
        .await
        .unwrap();
    apalis_sqlite::queries::reenqueue_orphaned(
        &runtime.store.pool,
        1,
        database::QUEUE,
        &WorkerFilter::Only("crashed".into()),
    )
    .await
    .unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, id, &owner, JobState::Exited { code: 0 }).await;
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"xx");
    assert_eq!(std::fs::read(output).unwrap(), b"firstreplay");
    stop(&mut worker, &runtime).await;
}
