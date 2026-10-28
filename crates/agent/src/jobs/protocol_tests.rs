use super::frame::JobRequest;
use super::protocol::handle_job_request;
use super::*;
use std::os::unix::fs::PermissionsExt;

pub(super) async fn fixture(script: &str) -> (tempfile::TempDir, Arc<JobRuntime>, String, JobSpec) {
    let temp = tempfile::tempdir().expect("private test root");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("jobs");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = runtime(JobStore::initialize_fresh(root).await.unwrap());
    let owner = "a".repeat(64);
    let artifacts = runtime.store.artifacts(&owner).unwrap();
    let bytes = std::fs::read(std::fs::canonicalize("/bin/sh").unwrap()).unwrap();
    let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let upload_name = format!("{source_sha256}.upload");
    let upload = artifacts.upload_root().join(&upload_name);
    std::fs::write(&upload, &bytes).unwrap();
    crate::jobs::restrict_private_path(&upload, false).unwrap();
    let source = artifacts
        .seal(&upload_name, &source_sha256, bytes.len() as u64)
        .unwrap();
    let spec = JobSpec {
        program: source.display().to_string(),
        args: vec!["-c".into(), script.into()],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256,
    };
    (temp, runtime, owner, spec)
}

pub(super) fn runtime(store: JobStore) -> Arc<JobRuntime> {
    let runner = store.acquire_runner().expect("exclusive runtime lease");
    Arc::new(JobRuntime {
        store,
        _runner: runner,
        start_lock: Mutex::new(()),
        slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
        channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
        accepting: AtomicBool::new(true),
        shutdown: processkit::CancellationToken::new(),
        active_jobs: std::sync::Mutex::new(HashMap::new()),
        unknown_permits: std::sync::Mutex::new(Vec::new()),
    })
}

pub(super) fn start(id: JobId, spec: &JobSpec) -> JobRequest {
    JobRequest::Run {
        id,
        spec: spec.clone(),
    }
}

#[tokio::test]
async fn lost_ack_retry_keeps_one_execution_raw_output_and_nonzero_exit() {
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, runtime, owner, spec) =
        fixture("printf x >> counter; printf '\\377\\000raw' ; printf diagnostic >&2; exit 23")
            .await;
    let mut worker = JobWorker::start(runtime.clone());
    let id = JobId::new();
    // The worker belongs to the Agent: discarding the ACK does not cancel it.
    let _lost_ack = handle_job_request(start(id, &spec), &runtime, &owner).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let record = runtime.store.lookup(id, &owner).await.unwrap();
            if record.state == (JobState::Exited { code: 23 }) {
                break;
            }
            assert!(matches!(
                record.state,
                JobState::Prepared | JobState::Running
            ));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker records its actual nonzero exit");
    let retry = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert!(retry.is_ok());
    assert_eq!(
        retry.unwrap()["state"],
        serde_json::json!(JobState::Exited { code: 23 })
    );
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"x");
    let output = handle_job_request(
        JobRequest::Logs {
            id,
            stream: JobOutput::Stdout,
            offset: 0,
        },
        &runtime,
        &owner,
    )
    .await;
    assert!(output.is_ok());
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(output.as_ref().unwrap()["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(raw, b"\xff\0raw");
    assert_eq!(output.as_ref().unwrap()["next_offset"], 5);
    assert_eq!(output.unwrap()["eof"], true);
    for request in [
        JobRequest::Status { id },
        JobRequest::Cancel { id },
        JobRequest::Logs {
            id,
            stream: JobOutput::Stderr,
            offset: 0,
        },
        start(id, &spec),
    ] {
        let response = handle_job_request(request, &runtime, &"b".repeat(64)).await;
        assert!(response.is_err());
    }
    let mut changed = spec;
    changed.args.push("different".into());
    assert!(
        !handle_job_request(start(id, &changed), &runtime, &owner)
            .await
            .is_ok()
    );
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"x");
    runtime.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn restart_after_committed_start_before_spawn_stays_interrupted_and_never_replays() {
    let (temp, old, owner, spec) = fixture("printf replayed > forbidden").await;
    let id = JobId::new();
    assert_eq!(old.store.admit(id, &owner, &spec).await.unwrap().id, id);
    old.store.claim_fixture(id, &owner).await.unwrap();
    drop(old);
    let store = JobStore::open(temp.path().join("jobs")).await.unwrap();
    store.recover_nonterminal().await.unwrap();
    let reopened = runtime(store);
    let response = handle_job_request(start(id, &spec), &reopened, &owner).await;
    assert!(response.is_ok());
    assert_eq!(
        response.unwrap()["state"],
        serde_json::json!(JobState::Interrupted)
    );
    assert!(!temp.path().join("forbidden").exists());
    assert!(reopened.store.claim_fixture(id, &owner).await.is_err());
    let cancel = handle_job_request(JobRequest::Cancel { id }, &reopened, &owner).await;
    assert!(cancel.is_err());
    assert!(
        reopened
            .store
            .lookup(id, &owner)
            .await
            .unwrap()
            .state
            .blocks_update()
    );
}

#[tokio::test]
async fn wrong_source_and_noncanonical_id_never_launch() {
    let (temp, runtime, owner, mut spec) = fixture("printf ran > forbidden").await;
    let id = JobId::new();
    let correct = spec.clone();
    spec.source_sha256 = "0".repeat(64);
    let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert!(response.is_err());
    assert!(runtime.store.lookup(id, &owner).await.is_err());
    assert!(serde_json::from_value::<JobRequest>(serde_json::json!({"op":"run", "id":"01234567-89AB-4CDE-8FAB-0123456789AB", "spec":correct})).is_err());
    assert!(!temp.path().join("forbidden").exists());
}

#[tokio::test]
async fn detached_worker_retains_runner_lease_until_process_teardown() {
    if !super::process_tests::native_containment_available() {
        return;
    }
    let (temp, runtime, owner, spec) = fixture("printf started > ready; sleep 300").await;
    let mut worker = JobWorker::start(runtime.clone());
    let observer = runtime.store.clone();
    let shutdown = runtime.shutdown.clone();
    let weak = Arc::downgrade(&runtime);
    let id = JobId::new();
    let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert!(response.is_ok());
    drop(runtime);
    let readiness = tokio::time::timeout(Duration::from_secs(5), async {
        while !temp.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let lease_was_retained = observer.acquire_runner().is_err();
    // Always stop the fixture tree before asserting the observed safety properties.
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), &mut worker.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while weak.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached worker finishes process-tree teardown");
    assert!(
        readiness.is_ok(),
        "real worker reached its readiness marker"
    );
    assert!(
        lease_was_retained,
        "a second Agent cannot acquire recovery ownership"
    );
    assert_eq!(
        observer.lookup(id, &owner).await.unwrap().state,
        JobState::Interrupted
    );
    // Weak::upgrade returns None when the last strong reference reaches zero,
    // which can precede completion of JobRuntime's File destructor.
    let lease = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(lease) = observer.acquire_runner() {
                break lease;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runner lease is released after its final destructor");
    drop(lease);
    observer.close().await;
}

#[tokio::test]
async fn sealed_source_admission_rejects_another_controller_without_creating_job() {
    let (temp, runtime, owner, spec) = fixture("printf forbidden > replay").await;
    let id = JobId::new();
    let foreign = "b".repeat(64);
    assert!(
        handle_job_request(start(id, &spec), &runtime, &foreign)
            .await
            .is_err()
    );
    assert!(runtime.store.lookup(id, &foreign).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM Jobs")
            .fetch_one(&runtime.store.pool)
            .await
            .unwrap(),
        0
    );
    assert!(!temp.path().join("replay").exists());
    handle_job_request(start(id, &spec), &runtime, &owner)
        .await
        .unwrap();
    for request in [
        JobRequest::Status { id },
        JobRequest::Cancel { id },
        JobRequest::Logs {
            id,
            stream: JobOutput::Stdout,
            offset: 0,
        },
        start(id, &spec),
    ] {
        assert!(
            handle_job_request(request, &runtime, &foreign)
                .await
                .is_err()
        );
    }
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Prepared
    );
}
