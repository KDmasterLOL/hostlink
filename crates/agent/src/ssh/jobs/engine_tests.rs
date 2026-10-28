use super::protocol::handle_job_request;
use super::tests::{fixture, runtime, start};
use super::*;
use apalis_core::{
    backend::{BackendConfig, WorkerFilter},
    worker::context::WorkerContext,
};

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
async fn start_only_commits_prepared_and_real_worker_polls_database() {
    let (temp, runtime, owner, spec) = fixture("printf x >> counter").await;
    let id = JobId::new();
    for _ in 0..2 {
        let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
        assert!(response.ok);
        assert_eq!(response.state, Some(JobState::Prepared));
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!temp.path().join("counter").exists());
    let backend = runtime.store.worker_backend();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM Jobs")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        "Pending"
    );
    // No SSH request wakes or invokes a handler after this point.
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, id, &owner, JobState::Exited { code: 0 }).await;
    // Poll past several intervals: delayed automatic ACK must not rewrite state.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Exited { code: 0 }
    );
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"x");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM StartedClaims")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        1
    );
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn crash_after_actual_dequeue_before_claim_is_unknown_and_blocks_update() {
    let (temp, old, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    old.store.admit(id, &owner, &spec).await.unwrap();
    let backend = old.store.worker_backend();
    let ctx = WorkerContext::from("crashed-before-claim");
    apalis_sqlite::queries::register_worker(
        backend.pool(),
        backend.config(),
        &ctx,
        "SqliteStorage",
    )
    .await
    .unwrap();
    let tasks = apalis_sqlite::queries::fetch_next(backend.pool(), backend.config(), &ctx)
        .await
        .unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(
        old.store.lookup(id, &owner).await.unwrap().state,
        JobState::Prepared
    );
    assert!(
        !crate::durable::active_ids(&temp.path().join("jobs"))
            .unwrap()
            .is_empty()
    );
    drop(old);
    let store = DurableStore::open(temp.path().join("jobs")).await.unwrap();
    let recovered = runtime(store);
    recovered.store.recover_nonterminal().await.unwrap();
    let mut worker = JobWorker::start(recovered.clone());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        recovered.store.lookup(id, &owner).await.unwrap().state,
        JobState::Interrupted
    );
    assert!(!temp.path().join("replay").exists());
    assert_eq!(
        crate::durable::active_ids(&temp.path().join("jobs")).unwrap(),
        [id.to_string()]
    );
    stop(&mut worker, &recovered).await;
}

#[tokio::test]
async fn real_orphan_reenqueue_of_started_job_never_executes_in_worker() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    runtime.store.claim_start(id, &owner).await.unwrap();
    let backend = runtime.store.worker_backend();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,last_seen) VALUES('old','hostlink-agent-v1','SqliteStorage',0)").execute(backend.pool()).await.unwrap();
    sqlx::query("UPDATE Jobs SET lock_by='old',lock_at=0")
        .execute(backend.pool())
        .await
        .unwrap();
    assert_eq!(
        apalis_sqlite::queries::reenqueue_orphaned(
            backend.pool(),
            1,
            backend.config().queue.as_ref(),
            &WorkerFilter::None
        )
        .await
        .unwrap(),
        1
    );
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(!runtime.accepting.load(Ordering::Acquire));
    assert!(!temp.path().join("replay").exists());
    assert!(crate::durable::active_ids(&temp.path().join("jobs")).is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM StartedClaims")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn prepared_cancel_and_source_failure_are_not_polled_as_retryable_failed() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    handle_job_request(start(id, &spec), &runtime, &owner).await;
    let cancel = super::wire::JobRequest::Cancel {
        version: 1,
        id: id.to_string(),
    };
    let cancelled = handle_job_request(cancel, &runtime, &owner).await;
    assert_eq!(cancelled.state, Some(JobState::Failed));
    let mut wrong = spec.clone();
    wrong.source_sha256 = "0".repeat(64);
    assert!(
        !handle_job_request(start(JobId::new(), &wrong), &runtime, &owner)
            .await
            .ok
    );
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!temp.path().join("replay").exists());
    assert!(runtime.accepting.load(Ordering::Acquire));
    let backend = runtime.store.worker_backend();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM Jobs WHERE status='Failed' AND attempts=1"
        )
        .fetch_one(backend.pool())
        .await
        .unwrap(),
        2
    );
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn worker_limits_processes_to_sixteen_and_cancels_every_tree() {
    let (temp, runtime, owner, spec) = fixture("sleep 300 & echo $! >> pids; wait").await;
    let mut worker = JobWorker::start(runtime.clone());
    let mut ids = Vec::new();
    for _ in 0..17 {
        let id = JobId::new();
        assert!(
            handle_job_request(start(id, &spec), &runtime, &owner)
                .await
                .ok
        );
        ids.push(id);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while std::fs::read_to_string(temp.path().join("pids"))
            .unwrap_or_default()
            .lines()
            .count()
            != 16
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pids = std::fs::read_to_string(temp.path().join("pids")).unwrap();
    assert_eq!(pids.lines().count(), 16);
    assert_eq!(runtime.slots.available_permits(), 0);
    stop(&mut worker, &runtime).await;
    for pid in pids.lines() {
        assert!(!crate::ssh::durable_job_tests::linux_process_is_running(
            pid.parse().unwrap()
        ));
    }
    for id in ids {
        assert!(matches!(
            runtime.store.lookup(id, &owner).await.unwrap().state,
            JobState::Prepared | JobState::Interrupted
        ));
    }
}

#[tokio::test]
async fn dequeued_claim_rejects_foreign_worker_task_owner_and_command() {
    let (_temp, runtime, owner, spec) = fixture("exit 0").await;
    let id = JobId::new();
    let Admission::Created(snapshot) = runtime.store.admit(id, &owner, &spec).await.unwrap() else {
        panic!("fresh admission")
    };
    let backend = runtime.store.worker_backend();
    let ctx = WorkerContext::from("claim-owner");
    apalis_sqlite::queries::register_worker(
        backend.pool(),
        backend.config(),
        &ctx,
        "SqliteStorage",
    )
    .await
    .unwrap();
    let mut tasks = apalis_sqlite::queries::fetch_next(backend.pool(), backend.config(), &ctx)
        .await
        .unwrap();
    let task_id = tasks.pop().unwrap().task_id().unwrap().to_string();
    assert!(
        runtime
            .store
            .claim_dequeued(&snapshot, &task_id, "foreign-worker")
            .await
            .is_err()
    );
    assert!(
        runtime
            .store
            .claim_dequeued(&snapshot, "foreign-task", ctx.name())
            .await
            .is_err()
    );
    let mut changed = snapshot.clone();
    changed.controller_key_sha256 = "b".repeat(64);
    assert!(
        runtime
            .store
            .claim_dequeued(&changed, &task_id, ctx.name())
            .await
            .is_err()
    );
    changed = snapshot.clone();
    changed.spec.args = vec!["-c".into(), "printf forbidden".into()];
    assert!(
        runtime
            .store
            .claim_dequeued(&changed, &task_id, ctx.name())
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM StartedClaims")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        runtime
            .store
            .claim_dequeued(&snapshot, &task_id, ctx.name())
            .await
            .unwrap()
            .state,
        JobState::Running
    );
    assert!(
        runtime
            .store
            .claim_dequeued(&snapshot, &task_id, ctx.name())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn backend_decode_failure_drains_an_already_running_tree() {
    let (temp, runtime, owner, spec) = fixture("sleep 300 & echo $! > pid; wait").await;
    let mut worker = JobWorker::start(runtime.clone());
    let id = JobId::new();
    assert!(
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .ok
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !temp.path().join("pid").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pid: u32 = std::fs::read_to_string(temp.path().join("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // Keep start_lock while publishing a deliberately corrupt queued payload;
    // no SSH admission or service claim can run between the two fixture writes.
    let lock = runtime.start_lock.lock().await;
    let poison = JobId::new();
    runtime.store.admit(poison, &owner, &spec).await.unwrap();
    let backend = runtime.store.worker_backend();
    sqlx::query("UPDATE Jobs SET job=? WHERE idempotency_key=?")
        .bind(b"invalid".as_slice())
        .bind(poison.to_string())
        .execute(backend.pool())
        .await
        .unwrap();
    drop(lock);
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(!runtime.accepting.load(Ordering::Acquire));
    assert!(!crate::ssh::durable_job_tests::linux_process_is_running(
        pid
    ));
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Interrupted
    );
}

#[tokio::test]
async fn recovery_seals_historical_failed_zero_attempts_without_rewriting_result() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    let expected = runtime
        .store
        .transition(id, &owner, JobState::Prepared, JobState::Failed)
        .await
        .unwrap();
    let backend = runtime.store.worker_backend();
    sqlx::query("UPDATE Jobs SET attempts=0,done_at=17")
        .execute(backend.pool())
        .await
        .unwrap();
    runtime.store.recover_nonterminal().await.unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(runtime.store.lookup(id, &owner).await.unwrap(), expected);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT done_at FROM Jobs")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        17
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT attempts FROM Jobs")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        1
    );
    assert!(!temp.path().join("replay").exists());
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn immediate_agent_restart_registers_without_heartbeat_wait_or_replay() {
    let (temp, old, owner, spec) = fixture("printf x >> counter").await;
    let id = JobId::new();
    let mut worker = JobWorker::start(old.clone());
    assert!(handle_job_request(start(id, &spec), &old, &owner).await.ok);
    wait_state(&old, id, &owner, JobState::Exited { code: 0 }).await;
    stop(&mut worker, &old).await;
    drop(old);
    let recovered = runtime(DurableStore::open(temp.path().join("jobs")).await.unwrap());
    recovered.store.recover_nonterminal().await.unwrap();
    let mut next = JobWorker::start(recovered.clone());
    assert_eq!(
        handle_job_request(start(id, &spec), &recovered, &owner)
            .await
            .state,
        Some(JobState::Exited { code: 0 })
    );
    let fresh = JobId::new();
    assert!(
        handle_job_request(start(fresh, &spec), &recovered, &owner)
            .await
            .ok
    );
    wait_state(&recovered, fresh, &owner, JobState::Exited { code: 0 }).await;
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"xx");
    let backend = recovered.store.worker_backend();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM Workers")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        1
    );
    stop(&mut next, &recovered).await;
}
