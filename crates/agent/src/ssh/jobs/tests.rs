use super::protocol::handle_job_request;
use super::wire::JobRequest;
use super::*;
use std::os::unix::fs::PermissionsExt;

pub(super) async fn fixture(script: &str) -> (tempfile::TempDir, Arc<JobRuntime>, String, JobSpec) {
    let temp = tempfile::tempdir().expect("private test root");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = temp.path().join("pinned-sh");
    std::fs::copy(std::fs::canonicalize("/bin/sh").unwrap(), &source).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
    let root = temp.path().join("jobs");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spec = JobSpec {
        program: source.display().to_string(),
        args: vec!["-c".into(), script.into()],
        cwd: Some(temp.path().to_path_buf()),
        source_sha256: format!("{:x}", Sha256::digest(std::fs::read(source).unwrap())),
    };
    let runtime = runtime(DurableStore::initialize_fresh(root).await.unwrap());
    (temp, runtime, "a".repeat(64), spec)
}

pub(super) fn runtime(store: DurableStore) -> Arc<JobRuntime> {
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
    })
}

pub(super) fn start(id: JobId, spec: &JobSpec) -> JobRequest {
    JobRequest::Start {
        version: 1,
        id: id.to_string(),
        spec: spec.clone(),
    }
}

#[tokio::test]
async fn lost_ack_retry_keeps_one_execution_raw_output_and_nonzero_exit() {
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
    assert!(retry.ok);
    assert_eq!(retry.state, Some(JobState::Exited { code: 23 }));
    assert_eq!(std::fs::read(temp.path().join("counter")).unwrap(), b"x");
    let output = handle_job_request(
        JobRequest::Output {
            version: 1,
            id: id.to_string(),
            stream: JobOutput::Stdout,
            offset: 0,
        },
        &runtime,
        &owner,
    )
    .await;
    assert!(output.ok);
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(output.data_base64.unwrap())
        .unwrap();
    assert_eq!(raw, b"\xff\0raw");
    assert_eq!(output.next_offset, Some(5));
    assert_eq!(output.eof, Some(true));
    for request in [
        JobRequest::Status {
            version: 1,
            id: id.to_string(),
        },
        JobRequest::Cancel {
            version: 1,
            id: id.to_string(),
        },
        JobRequest::Output {
            version: 1,
            id: id.to_string(),
            stream: JobOutput::Stderr,
            offset: 0,
        },
        start(id, &spec),
    ] {
        let response = handle_job_request(request, &runtime, &"b".repeat(64)).await;
        assert!(!response.ok);
        assert_eq!(response.error, Some("job belongs to another controller"));
    }
    let mut changed = spec;
    changed.args.push("different".into());
    assert!(
        !handle_job_request(start(id, &changed), &runtime, &owner)
            .await
            .ok
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
    assert!(matches!(
        old.store.admit(id, &owner, &spec).await.unwrap(),
        Admission::Created(_)
    ));
    old.store.claim_start(id, &owner).await.unwrap();
    drop(old);
    let store = DurableStore::open(temp.path().join("jobs")).await.unwrap();
    store.recover_nonterminal().await.unwrap();
    let reopened = runtime(store);
    let response = handle_job_request(start(id, &spec), &reopened, &owner).await;
    assert!(response.ok);
    assert_eq!(response.state, Some(JobState::Interrupted));
    assert!(!temp.path().join("forbidden").exists());
    assert!(reopened.store.claim_start(id, &owner).await.is_err());
    let cancel = handle_job_request(
        JobRequest::Cancel {
            version: 1,
            id: id.to_string(),
        },
        &reopened,
        &owner,
    )
    .await;
    assert!(!cancel.ok);
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
    assert_eq!(
        response.error,
        Some("source executable verification failed")
    );
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Failed
    );
    assert!(
        !handle_job_request(start(id, &correct), &runtime, &owner)
            .await
            .ok
    );
    let response = handle_job_request(
        JobRequest::Start {
            version: 1,
            id: "01234567-89AB-4CDE-8FAB-0123456789AB".into(),
            spec: correct,
        },
        &runtime,
        &owner,
    )
    .await;
    assert_eq!(response.error, Some("invalid job ID"));
    assert!(!temp.path().join("forbidden").exists());
}

#[tokio::test]
async fn detached_worker_retains_runner_lease_until_process_teardown() {
    let (temp, runtime, owner, spec) = fixture("printf started > ready; sleep 300").await;
    let mut worker = JobWorker::start(runtime.clone());
    let observer = runtime.store.clone();
    let shutdown = runtime.shutdown.clone();
    let weak = Arc::downgrade(&runtime);
    let id = JobId::new();
    let response = handle_job_request(start(id, &spec), &runtime, &owner).await;
    assert!(response.ok);
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
    let lease = observer
        .acquire_runner()
        .expect("lease released after final worker drop");
    drop(lease);
    observer.close().await;
}
