use super::protocol::handle_job_request;
use super::protocol_tests::{fixture, runtime, start};
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
async fn managed_artifact_root_changed_after_admission_fails_without_replay() {
    use std::os::unix::fs::PermissionsExt;
    let (outer, store, owner, spec) = super::source_tests::fixture().await;
    let runtime = runtime(store);
    let id = JobId::new();
    handle_job_request(start(id, &spec), &runtime, &owner)
        .await
        .unwrap();
    // Only invalidate the executable store, not the independent SQLite
    // directory, so the worker can record a definite source rejection.
    let artifacts = outer.path().join("install/artifacts");
    std::fs::set_permissions(&artifacts, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(verify_job_source(&runtime.store, &owner, &spec).is_err());
    let fresh = JobId::new();
    assert!(
        handle_job_request(start(fresh, &spec), &runtime, &owner)
            .await
            .is_err()
    );
    assert!(runtime.store.lookup(fresh, &owner).await.is_err());
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, id, &owner, JobState::Failed).await;
    let record = runtime.store.lookup(id, &owner).await.unwrap();
    assert!(record.started);
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        assert_eq!(
            runtime.store.read_output(&record, stream, 0).unwrap(),
            (vec![], 0, true)
        );
    }
    restrict_private_path(&artifacts, true).unwrap();
    verify_job_source(&runtime.store, &owner, &spec).unwrap();
    assert_eq!(
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .unwrap()["state"],
        serde_json::json!(JobState::Failed)
    );
    assert!(runtime.store.claim_fixture(id, &owner).await.is_err());
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn start_only_commits_prepared_and_real_worker_polls_database() {
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, runtime, owner, spec) = fixture("printf x >> counter").await;
    let id = JobId::new();
    for _ in 0..2 {
        let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
        assert!(response.is_ok());
        assert_eq!(
            response.unwrap()["state"],
            serde_json::json!(JobState::Prepared)
        );
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
async fn source_removed_after_start_ack_has_complete_failed_spools_without_execution() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    let accepted = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert_eq!(
        accepted.unwrap()["state"],
        serde_json::json!(JobState::Prepared)
    );
    // The authenticated request was accepted, but the path no longer has the
    // originally pinned bytes when Apalis eventually dequeues the task.
    std::fs::remove_file(&spec.program).unwrap();
    assert_eq!(
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .unwrap()["state"],
        serde_json::json!(JobState::Prepared),
        "lost ACK retry survives source removal without granting another start"
    );
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, id, &owner, JobState::Failed).await;
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        let path = runtime.store.output_path(id, stream);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
        assert_eq!(
            runtime
                .store
                .read_fixture_output(id, &owner, stream, 0)
                .await
                .unwrap(),
            (Vec::new(), 0, true)
        );
    }
    assert!(
        crate::jobs::active_ids(&temp.path().join("jobs"))
            .unwrap()
            .is_empty()
    );
    assert!(!temp.path().join("replay").exists());
    assert_eq!(
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .unwrap()["state"],
        serde_json::json!(JobState::Failed)
    );
    assert!(runtime.store.claim_fixture(id, &owner).await.is_err());
    stop(&mut worker, &runtime).await;
}

#[tokio::test]
async fn changed_sealed_source_after_admission_is_failed_without_launch_or_replay() {
    use std::os::unix::fs::PermissionsExt;
    for corrupt_parent in [false, true] {
        let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
        let id = JobId::new();
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .unwrap();
        let program = Path::new(&spec.program);
        let original = std::fs::read(program).unwrap();
        if corrupt_parent {
            std::fs::set_permissions(
                program.parent().unwrap(),
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        } else {
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(program, b"#!/bin/sh\nprintf forbidden > replay\n").unwrap();
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert!(verify_job_source(&runtime.store, &owner, &spec).is_err());
        let mut worker = JobWorker::start(runtime.clone());
        wait_state(&runtime, id, &owner, JobState::Failed).await;
        let record = runtime.store.lookup(id, &owner).await.unwrap();
        assert!(record.started);
        for stream in [JobOutput::Stdout, JobOutput::Stderr] {
            assert_eq!(
                runtime.store.read_output(&record, stream, 0).unwrap(),
                (vec![], 0, true)
            );
        }
        assert!(!temp.path().join("replay").exists());
        // Restoring the source cannot replenish the consumed execution fence.
        restrict_private_path(program.parent().unwrap(), true).unwrap();
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(program, original).unwrap();
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o500)).unwrap();
        verify_job_source(&runtime.store, &owner, &spec).unwrap();
        assert_eq!(
            handle_job_request(start(id, &spec), &runtime, &owner)
                .await
                .unwrap()["state"],
            serde_json::json!(JobState::Failed)
        );
        assert!(runtime.store.claim_fixture(id, &owner).await.is_err());
        stop(&mut worker, &runtime).await;
        assert!(!temp.path().join("replay").exists());
    }
}

#[tokio::test]
async fn failed_spool_preparation_quarantines_capacity_and_stops_worker() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    let accepted = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert_eq!(
        accepted.unwrap()["state"],
        serde_json::json!(JobState::Prepared)
    );
    let occupied = runtime.store.output_path(id, JobOutput::Stdout);
    std::fs::write(&occupied, b"invalid pre-existing spool").unwrap();
    crate::jobs::restrict_private_path(&occupied, false).unwrap();

    let mut worker = JobWorker::start(runtime.clone());
    let result = tokio::time::timeout(Duration::from_secs(10), &mut worker.task)
        .await
        .expect("failed worker must stop instead of releasing an unknown process slot")
        .expect("worker supervisor joined");
    assert!(result.is_err());
    assert!(!runtime.accepting.load(Ordering::Acquire));
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Interrupted
    );
    assert_eq!(
        runtime
            .unknown_permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1,
        "unconfirmed work cannot release its permit"
    );
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS - 1);
    assert_eq!(
        crate::jobs::active_ids(&temp.path().join("jobs")).unwrap(),
        vec![id.to_string()]
    );
    assert!(!temp.path().join("replay").exists());
}

#[tokio::test]
async fn restart_before_dequeue_executes_unclaimed_job_once() {
    restart_unclaimed(false).await;
}

#[tokio::test]
async fn restart_after_actual_dequeue_before_claim_executes_once() {
    restart_unclaimed(true).await;
}

async fn restart_unclaimed(dequeued: bool) {
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, old, owner, spec) = fixture("printf x >> counter; exit 7").await;
    let id = JobId::new();
    old.store.admit(id, &owner, &spec).await.unwrap();
    if dequeued {
        let backend = old.store.worker_backend();
        let ctx = WorkerContext::from(WORKER_NAME);
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
    }
    drop(old);
    let recovered = runtime(JobStore::open(temp.path().join("jobs")).await.unwrap());
    recovered.store.recover_nonterminal().await.unwrap();
    assert_eq!(
        recovered.store.lookup(id, &owner).await.unwrap().state,
        JobState::Prepared
    );
    let native: (String, i64, i64) = sqlx::query_as(
        "SELECT status,attempts,(SELECT count(*) FROM StartedClaims) FROM Jobs WHERE id=?",
    )
    .bind(id.to_string())
    .fetch_one(&recovered.store.pool)
    .await
    .unwrap();
    assert_eq!(
        native,
        (if dequeued { "Queued" } else { "Pending" }.into(), 0, 0)
    );
    let mut worker = JobWorker::start(recovered.clone());
    wait_state(&recovered, id, &owner, JobState::Exited { code: 7 }).await;
    recovered.store.admit(id, &owner, &spec).await.unwrap();
    stop(&mut worker, &recovered).await;
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"x");
    assert!(
        crate::jobs::active_ids(&temp.path().join("jobs"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM StartedClaims")
            .fetch_one(&recovered.store.pool)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn real_orphan_reenqueue_of_started_job_never_executes_in_worker() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    runtime.store.claim_fixture(id, &owner).await.unwrap();
    let backend = runtime.store.worker_backend();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,last_seen) VALUES('old','hostlink-agent','SqliteStorage',0)").execute(backend.pool()).await.unwrap();
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
    assert_eq!(
        crate::jobs::active_ids(&temp.path().join("jobs")).unwrap(),
        vec![id.to_string()]
    );
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
    handle_job_request(start(id, &spec), &runtime, &owner)
        .await
        .unwrap();
    let cancel = super::frame::JobRequest::Cancel { id };
    let cancelled = handle_job_request(cancel, &runtime, &owner).await;
    assert_eq!(
        cancelled.unwrap()["state"],
        serde_json::json!(JobState::Failed)
    );
    let bad_id = JobId::new();
    assert!(
        handle_job_request(start(bad_id, &spec), &runtime, &owner)
            .await
            .is_ok()
    );
    // It was authenticated and accepted, then the sealed source disappeared
    // before dequeue. No OS spawn is needed for this definite failure.
    std::fs::remove_file(&spec.program).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    wait_state(&runtime, bad_id, &owner, JobState::Failed).await;
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
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, runtime, owner, spec) = fixture("sleep 300 & echo $! >> pids; wait").await;
    let mut worker = JobWorker::start(runtime.clone());
    let mut ids = Vec::new();
    for _ in 0..17 {
        let id = JobId::new();
        let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
        assert!(
            response.is_ok(),
            "request {}: {response:?}; accepting={}",
            ids.len(),
            runtime.accepting.load(Ordering::Acquire)
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
        assert!(!super::process_tests::linux_process_is_running(
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
    let snapshot = runtime.store.admit(id, &owner, &spec).await.unwrap();
    let snapshot = snapshot.job;
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
    assert_eq!(
        task_id,
        id.to_string(),
        "caller and native task ID must be identical"
    );
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
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, runtime, owner, spec) = fixture("sleep 300 & echo $! > pid; wait").await;
    let mut worker = JobWorker::start(runtime.clone());
    let id = JobId::new();
    assert!(
        handle_job_request(start(id, &spec), &runtime, &owner)
            .await
            .is_ok()
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
    assert!(!super::process_tests::linux_process_is_running(pid));
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Interrupted
    );
}

#[tokio::test]
async fn corrupt_failed_attempt_count_cannot_enable_retry() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    runtime
        .store
        .transition(id, &owner, JobState::Prepared, JobState::Failed)
        .await
        .unwrap();
    let backend = runtime.store.worker_backend();
    sqlx::query("UPDATE Jobs SET attempts=0")
        .execute(backend.pool())
        .await
        .unwrap();
    assert!(runtime.store.lookup(id, &owner).await.is_err());
    assert!(runtime.store.recover_nonterminal().await.is_err());
    assert!(crate::jobs::active_ids(&temp.path().join("jobs")).is_err());
    assert!(!temp.path().join("replay").exists());
}

#[tokio::test]
async fn immediate_agent_restart_registers_without_heartbeat_wait_or_replay() {
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, old, owner, spec) = fixture("printf x >> counter").await;
    let id = JobId::new();
    let mut worker = JobWorker::start(old.clone());
    assert!(
        handle_job_request(start(id, &spec), &old, &owner)
            .await
            .is_ok()
    );
    wait_state(&old, id, &owner, JobState::Exited { code: 0 }).await;
    stop(&mut worker, &old).await;
    drop(old);
    let recovered = runtime(JobStore::open(temp.path().join("jobs")).await.unwrap());
    recovered.store.recover_nonterminal().await.unwrap();
    let mut next = JobWorker::start(recovered.clone());
    assert_eq!(
        handle_job_request(start(id, &spec), &recovered, &owner)
            .await
            .unwrap()["state"],
        serde_json::json!(JobState::Exited { code: 0 })
    );
    let fresh = JobId::new();
    assert!(
        handle_job_request(start(fresh, &spec), &recovered, &owner)
            .await
            .is_ok()
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
async fn uncertain_unclaimed_native_attempts_cannot_authorize_execution_after_restart() {
    let positive_containment = super::process_tests::native_containment_available();
    for result in [None, Some(r#"{"Err":"not an Apalis requeue"}"#)] {
        let (temp, old, owner, spec) = fixture("printf forbidden > replay").await;
        let id = JobId::new();
        old.store.admit(id, &owner, &spec).await.unwrap();
        sqlx::query("UPDATE Jobs SET attempts=1,last_result=? WHERE id=?")
            .bind(result)
            .bind(id.to_string())
            .execute(&old.store.pool)
            .await
            .unwrap();
        drop(old);
        let recovered = runtime(JobStore::open(temp.path().join("jobs")).await.unwrap());
        recovered.store.recover_nonterminal().await.unwrap();
        let native: String = sqlx::query_scalar("SELECT status FROM Jobs WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&recovered.store.pool)
            .await
            .unwrap();
        assert_eq!(native, "Killed");
        assert_eq!(
            recovered.store.lookup(id, &owner).await.unwrap().state,
            JobState::Interrupted
        );
        let mut worker = JobWorker::start(recovered.clone());
        // A fresh job proves polling is live while the uncertain one is fenced.
        // Unsupported containment must produce a definite pre-launch failure.
        let good = JobId::new();
        let mut good_spec = spec;
        good_spec.args = vec!["-c".into(), "exit 0".into()];
        recovered
            .store
            .admit(good, &owner, &good_spec)
            .await
            .unwrap();
        let expected = if positive_containment {
            JobState::Exited { code: 0 }
        } else {
            JobState::Failed
        };
        wait_state(&recovered, good, &owner, expected).await;
        stop(&mut worker, &recovered).await;
        assert!(!temp.path().join("replay").exists());
        assert_eq!(
            crate::jobs::active_ids(&temp.path().join("jobs")).unwrap(),
            [id.to_string()]
        );
    }
}

#[tokio::test]
async fn updater_lock_rejects_run_and_dequeue_without_blocking_agent_shutdown() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    let snapshot = runtime.store.admit(id, &owner, &spec).await.unwrap().job;
    let backend = runtime.store.worker_backend();
    let ctx = WorkerContext::from("busy-claim-fixture");
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
    let task_id = tasks[0].task_id().unwrap().to_string();
    let updater = acquire_update_lock(temp.path()).unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    let new = JobId::new();
    let run = handle_job_request(start(new, &spec), &runtime, &owner);
    let claim = async {
        let _start = runtime.start_lock.lock().await;
        runtime
            .store
            .claim_dequeued(&snapshot, &task_id, ctx.name())
            .await
    };
    let shutdown = async {
        runtime.shutdown.cancel();
        (&mut worker.task).await.unwrap()
    };
    let (run, claim, shutdown) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(run, claim, shutdown)
    })
    .await
    .expect("held update.lock must not block STOP/start_lock");
    assert_eq!(run, Err("Agent update busy"));
    assert_eq!(claim.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    shutdown.unwrap();
    assert!(!temp.path().join("replay").exists());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM StartedClaims")
            .fetch_one(backend.pool())
            .await
            .unwrap(),
        0
    );
    assert!(
        runtime.store.lookup(new, &owner).await.is_err(),
        "Busy must not enqueue or retry"
    );
    drop(updater);
    assert_eq!(
        runtime.store.admit(id, &owner, &spec).await.unwrap().state,
        JobState::Prepared
    );
}
