use super::*;
use crate::jobs::{protocol::handle_job_request, protocol_tests::runtime, tests::*};

async fn wait_native(runtime: &JobRuntime, status: &str, count: i64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs WHERE status=?")
                .bind(status)
                .fetch_one(&runtime.store.pool)
                .await
                .unwrap();
            if actual == count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn stop(worker: &mut JobWorker, runtime: &JobRuntime) {
    runtime.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), &mut worker.task)
        .await
        .expect("update.lock must not prevent shutdown")
        .unwrap()
        .unwrap();
}

async fn assert_unclaimed(runtime: &JobRuntime, count: i64) {
    let native: (i64, i64) = sqlx::query_as(
        "SELECT count(*),sum(attempts) FROM Jobs WHERE status='Queued' AND NOT EXISTS(SELECT 1 FROM StartedClaims c WHERE c.task_id=Jobs.id)",
    )
    .fetch_one(&runtime.store.pool)
    .await
    .unwrap();
    assert_eq!(native, (count, 0));
    assert!(!runtime.shutdown.is_cancelled());
    assert!(runtime.accepting.load(Ordering::Acquire));
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
}

#[tokio::test]
async fn updater_busy_retries_same_dequeues_without_stopping_worker_or_losing_tasks() {
    let (root, store) = fixture().await;
    let runtime = runtime(store);
    let ids = [JobId::new(), JobId::new()];
    for id in ids {
        // Storage-only fixture: deliberately unauthorized source must fail at
        // the real pre-spawn gate after claim. No ancestor/containment bypass.
        runtime.store.admit(id, &owner(), &sample()).await.unwrap();
    }
    let updater = acquire_update_lock(root.path()).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    wait_native(&runtime, "Queued", 2).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_unclaimed(&runtime, 2).await;
    assert!(!worker.task.is_finished());
    assert_eq!(active_ids(&runtime.store.root).unwrap().len(), 2);
    drop(updater);
    wait_native(&runtime, "Failed", 2).await;
    for id in ids {
        let record = runtime.store.lookup(id, &owner()).await.unwrap();
        assert!(record.started);
        assert!(runtime.store.claim_fixture(id, &owner()).await.is_err());
        for stream in [JobOutput::Stdout, JobOutput::Stderr] {
            assert_eq!(
                runtime.store.read_output(&record, stream, 0).unwrap(),
                (vec![], 0, true)
            );
        }
    }
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims")
        .fetch_one(&runtime.store.pool)
        .await
        .unwrap();
    assert_eq!(claims, 2);
    assert!(!runtime.shutdown.is_cancelled());
    assert!(runtime.accepting.load(Ordering::Acquire));
    assert!(active_ids(&runtime.store.root).unwrap().is_empty());
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn shutdown_during_updater_busy_recovers_only_unclaimed_delivery() {
    let (root, store) = fixture().await;
    let old = runtime(store);
    let spent = JobId::new();
    old.store.admit(spent, &owner(), &sample()).await.unwrap();
    old.store.claim_fixture(spent, &owner()).await.unwrap();
    let queued = JobId::new();
    old.store.admit(queued, &owner(), &sample()).await.unwrap();
    let updater = acquire_update_lock(root.path()).unwrap();
    let mut worker = JobWorker::start(old.clone());
    wait_native(&old, "Queued", 1).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_unclaimed(&old, 1).await;
    stop(&mut worker, &old).await;
    drop(worker);
    drop(old);

    let recovered = runtime(JobStore::open(root.path().join("jobs")).await.unwrap());
    recovered.store.recover_nonterminal().await.unwrap();
    assert_eq!(
        recovered
            .store
            .lookup(queued, &owner())
            .await
            .unwrap()
            .state,
        JobState::Prepared
    );
    assert_eq!(
        recovered.store.lookup(spent, &owner()).await.unwrap().state,
        JobState::Interrupted
    );
    drop(updater);
    let mut worker = JobWorker::start(recovered.clone());
    wait_native(&recovered, "Failed", 1).await;
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims")
        .fetch_one(&recovered.store.pool)
        .await
        .unwrap();
    assert_eq!(claims, 2);
    assert_eq!(
        recovered.store.lookup(spent, &owner()).await.unwrap().state,
        JobState::Interrupted
    );
    assert_eq!(
        active_ids(&recovered.store.root).unwrap(),
        [spent.to_string()]
    );
    stop(&mut worker, &recovered).await;
}

#[tokio::test]
async fn cancel_during_updater_busy_is_reread_before_claim() {
    let (root, store) = fixture().await;
    let runtime = runtime(store);
    let id = JobId::new();
    runtime.store.admit(id, &owner(), &sample()).await.unwrap();
    let updater = acquire_update_lock(root.path()).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    wait_native(&runtime, "Queued", 1).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_unclaimed(&runtime, 1).await;
    tokio::time::timeout(
        Duration::from_secs(1),
        handle_job_request(
            crate::jobs::frame::JobRequest::Cancel { id },
            &runtime,
            &owner(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    drop(updater);
    wait_native(&runtime, "Failed", 1).await;
    assert!(!runtime.store.lookup(id, &owner()).await.unwrap().started);
    stop(&mut worker, &runtime).await;
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims")
        .fetch_one(&runtime.store.pool)
        .await
        .unwrap();
    assert_eq!(claims, 0);
}

#[tokio::test]
async fn updater_busy_does_not_cancel_an_already_running_job() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    // Some sandboxed Linux hosts map root-owned ancestors to nobody (UID 65534).
    // This is a native execution test, not a request to bypass source trust.
    if let Err(error) = crate::jobs::private_fs::validate_source_ancestors(
        &std::env::current_dir().expect("test working directory"),
    ) {
        eprintln!(
            "NOT RUN [updater Busy + running process]: source ancestors cannot be trusted: {error}"
        );
        assert_ne!(
            std::env::var("HOSTLINK_REQUIRE_NATIVE_CONTAINMENT").as_deref(),
            Ok("1"),
            "required native execution cannot skip untrusted source ancestors"
        );
        return;
    }
    let (root, runtime, owner, spec) = crate::jobs::protocol_tests::fixture(
        "printf ready > ready; while [ ! -f release ]; do sleep 0.05; done; exit 7",
    )
    .await;
    let running = JobId::new();
    runtime.store.admit(running, &owner, &spec).await.unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Force the real second dequeue to encounter update.lock after admission.
    let start = runtime.start_lock.lock().await;
    let queued = JobId::new();
    let mut next = spec;
    next.args = vec!["-c".into(), "exit 0".into()];
    runtime.store.admit(queued, &owner, &next).await.unwrap();
    let updater = acquire_update_lock(root.path()).unwrap();
    drop(start);
    wait_native(&runtime, "Queued", 1).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!worker.task.is_finished());
    assert!(!runtime.shutdown.is_cancelled());
    assert!(runtime.accepting.load(Ordering::Acquire));
    assert!(!runtime.active_jobs.lock().unwrap()[&running].is_cancelled());
    assert_eq!(
        runtime.store.lookup(running, &owner).await.unwrap().state,
        JobState::Running
    );
    assert!(!runtime.store.lookup(queued, &owner).await.unwrap().started);
    assert_eq!(active_ids(&runtime.store.root).unwrap().len(), 2);
    drop(updater);
    wait_native(&runtime, "Done", 1).await;
    fs::write(root.path().join("release"), b"release").unwrap();
    wait_native(&runtime, "Done", 2).await;
    assert_eq!(
        runtime.store.lookup(running, &owner).await.unwrap().state,
        JobState::Exited { code: 7 }
    );
    assert_eq!(
        runtime.store.lookup(queued, &owner).await.unwrap().state,
        JobState::Exited { code: 0 }
    );
    stop(&mut worker, &runtime).await;
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
}
