use super::*;
use crate::jobs::process_tests::prepared_job;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn cancelled_signal_and_flushed_spools_do_not_mask_io_read_error() {
    for read_error in [true, false] {
        let (_root, store) = crate::jobs::tests::fixture().await;
        let runtime = crate::jobs::protocol_tests::runtime(store);
        let owner = crate::jobs::tests::owner();
        let id = JobId::new();
        runtime
            .store
            .admit(id, &owner, &crate::jobs::tests::sample())
            .await
            .unwrap();
        runtime.store.claim_fixture(id, &owner).await.unwrap();
        let cancel = runtime.shutdown.child_token();
        let ends = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let (out, out_sync) = open_job_output(&runtime, id, JobOutput::Stdout).unwrap();
        let (err, err_sync) = open_job_output(&runtime, id, JobOutput::Stderr).unwrap();
        let mut out = CappedOutputWriter::new(out, cancel.clone(), ends[0].clone());
        let mut err = CappedOutputWriter::new(err, cancel.clone(), ends[1].clone());
        out.write_all(b"partial stdout").await.unwrap();
        err.write_all(b"partial stderr").await.unwrap();
        // Match pinned pump.rs: raw tees flush even on a read-error exit.
        out.flush().await.unwrap();
        err.flush().await.unwrap();
        assert!(ends.iter().all(|end| end.load(Ordering::Acquire)));
        cancel.cancel();
        // Fault injection at the actual finisher boundary, without mocking a
        // reader or ProcessKit. The clean outcome covers a confirmed group kill.
        let outcome = if read_error {
            Err(processkit::ErrorReason::Io(io::Error::other("pipe read failed")).into())
        } else {
            Ok(processkit::Outcome::Signalled(Some(9)))
        };
        let result = finish_job(
            &runtime,
            &owner,
            id,
            &cancel,
            outcome,
            &ends,
            (out_sync, err_sync),
        )
        .await;
        assert_eq!(result.is_err(), read_error);
        let record = runtime.store.lookup(id, &owner).await.unwrap();
        assert_eq!(
            record.state,
            if read_error {
                JobState::Interrupted
            } else {
                JobState::Failed
            }
        );
        for stream in [JobOutput::Stdout, JobOutput::Stderr] {
            let (bytes, _, eof) = runtime.store.read_output(&record, stream, 0).unwrap();
            assert!(!bytes.is_empty());
            assert_eq!(eof, !read_error);
        }
        assert_eq!(
            active_ids(&runtime.store.root).unwrap().is_empty(),
            !read_error
        );
    }
}

#[tokio::test]
async fn authenticated_cancel_waiting_at_spawn_gate_prevents_execution() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let (_root, runtime, owner, record) = prepared_job(
        vec!["-c".into(), "printf forbidden > cancelled-marker".into()],
        cwd.path(),
    )
    .await;
    let id = record.id;
    let active = runtime.shutdown.child_token();
    runtime
        .active_jobs
        .lock()
        .unwrap()
        .insert(id, active.clone());
    let gate = runtime.start_lock.lock().await;
    let cancel = crate::jobs::protocol::handle_job_request(
        crate::jobs::frame::JobRequest::Cancel { id },
        &runtime,
        &owner,
    );
    tokio::pin!(cancel);
    // Poll the real authenticated request into Tokio Mutex's FIFO wait queue
    // before run_job reaches the same gate. No timing-dependent sleeps.
    assert!(futures::poll!(&mut cancel).is_pending());
    let run = run_job(runtime.clone(), owner.clone(), record, active.clone());
    tokio::pin!(run);
    assert!(futures::poll!(&mut run).is_pending());
    drop(gate);
    let (cancelled, completed) = tokio::join!(cancel, run);
    cancelled.unwrap();
    completed.unwrap();
    assert!(active.is_cancelled());
    assert!(!cwd.path().join("cancelled-marker").exists());
    let record = runtime.store.lookup(id, &owner).await.unwrap();
    assert_eq!(record.state, JobState::Failed);
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        assert_eq!(
            runtime.store.read_output(&record, stream, 0).unwrap(),
            (vec![], 0, true)
        );
    }
}

#[tokio::test]
async fn clean_user_cancel_confirms_failed_and_worker_continues() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    let (root, runtime, owner, spec) = crate::jobs::protocol_tests::fixture(
        "printf ready > ready; printf output; printf diagnostic >&2; sleep 300",
    )
    .await;
    let id = JobId::new();
    runtime.store.admit(id, &owner, &spec).await.unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    crate::jobs::protocol::handle_job_request(
        crate::jobs::frame::JobRequest::Cancel { id },
        &runtime,
        &owner,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while runtime.store.lookup(id, &owner).await.unwrap().state != JobState::Failed {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let record = runtime.store.lookup(id, &owner).await.unwrap();
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        assert!(runtime.store.read_output(&record, stream, 0).unwrap().2);
    }
    assert!(!runtime.shutdown.is_cancelled());
    assert!(runtime.accepting.load(Ordering::Acquire));
    let second = JobId::new();
    let mut next = spec;
    next.args = vec!["-c".into(), "exit 7".into()];
    runtime.store.admit(second, &owner, &next).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.store.lookup(second, &owner).await.unwrap().state
            != (JobState::Exited { code: 7 })
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    runtime.shutdown.cancel();
    (&mut worker.task).await.unwrap().unwrap();
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
    assert!(runtime.unknown_permits.lock().unwrap().is_empty());
}

#[test]
fn containment_policy_never_trusts_posix_fallback() {
    assert!(!trusted_mechanism(processkit::Mechanism::ProcessGroup));
    assert!(trusted_mechanism(processkit::Mechanism::CgroupV2));
    assert!(!trusted_mechanism(processkit::Mechanism::JobObject));
    assert!(!trusted_mechanism(processkit::Mechanism::ProcessReaper));
}

#[tokio::test]
async fn unsupported_native_backend_fails_without_spawn_retry_or_quarantine() {
    let group = processkit::ProcessGroup::new().unwrap();
    if trusted_mechanism(group.mechanism()) {
        eprintln!(
            "NOT RUN: native fallback rejection requires an unsupported backend; actual: {:?}",
            group.mechanism()
        );
        return;
    }
    assert_eq!(group.mechanism(), processkit::Mechanism::ProcessGroup);
    let (root, runtime, owner, spec) = crate::jobs::protocol_tests::fixture(
        "printf forbidden > launched; setsid sh -c 'printf escaped > escaped'",
    )
    .await;
    let mut worker = JobWorker::start(runtime.clone());
    for _ in 0..2 {
        let id = JobId::new();
        let request = || crate::jobs::protocol_tests::start(id, &spec);
        super::super::protocol::handle_job_request(request(), &runtime, &owner)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.store.lookup(id, &owner).await.unwrap().state != JobState::Failed {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let record = runtime.store.lookup(id, &owner).await.unwrap();
        assert!(record.started, "rejected claimed start remains spent");
        for stream in [JobOutput::Stdout, JobOutput::Stderr] {
            assert_eq!(
                runtime.store.read_output(&record, stream, 0).unwrap(),
                (vec![], 0, true)
            );
        }
        assert_eq!(
            super::super::protocol::handle_job_request(request(), &runtime, &owner)
                .await
                .unwrap()["state"],
            serde_json::json!(JobState::Failed)
        );
        assert!(runtime.store.claim_fixture(id, &owner).await.is_err());
        assert!(runtime.accepting.load(Ordering::Acquire));
        assert!(!runtime.shutdown.is_cancelled());
        assert!(runtime.unknown_permits.lock().unwrap().is_empty());
        assert!(
            crate::jobs::active_ids(&runtime.store.root)
                .unwrap()
                .is_empty()
        );
        assert!(!root.path().join("launched").exists());
        assert!(!root.path().join("escaped").exists());
    }
    runtime.shutdown.cancel();
    (&mut worker.task).await.unwrap().unwrap();
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
    let attempts: Vec<i64> = sqlx::query_scalar("SELECT attempts FROM Jobs")
        .fetch_all(&runtime.store.pool)
        .await
        .unwrap();
    assert_eq!(attempts, vec![1, 1]);
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM StartedClaims")
        .fetch_one(&runtime.store.pool)
        .await
        .unwrap();
    assert_eq!(claims, 2);
}

#[tokio::test]
async fn fsync_and_real_exit_cannot_complete_either_unflushed_pump() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    // Deterministic fault injection at the post-drain boundary: successful real
    // child exit + fsynced partial files, but one or both tee tasks never flushed.
    // No five-second timeout or fake ProcessKit runner is needed.
    for flushed in [[false, false], [true, false], [false, true]] {
        let cwd = tempfile::tempdir().unwrap();
        let (_root, runtime, owner, record) =
            prepared_job(vec!["-c".into(), "exit 7".into()], cwd.path()).await;
        let ends = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let (out, mut out_sync) = open_job_output(&runtime, record.id, JobOutput::Stdout).unwrap();
        let (err, mut err_sync) = open_job_output(&runtime, record.id, JobOutput::Stderr).unwrap();
        std::io::Write::write_all(&mut out_sync, b"partial-out").unwrap();
        std::io::Write::write_all(&mut err_sync, b"partial-err").unwrap();
        out_sync.sync_all().unwrap();
        err_sync.sync_all().unwrap();
        let cancel = processkit::CancellationToken::new();
        let mut out = CappedOutputWriter::new(out, cancel.clone(), ends[0].clone());
        let mut err = CappedOutputWriter::new(err, cancel.clone(), ends[1].clone());
        if flushed[0] {
            out.flush().await.unwrap();
        }
        if flushed[1] {
            err.flush().await.unwrap();
        }
        let outcome = processkit::Command::new(&record.spec.program)
            .args(&record.spec.args)
            .start()
            .await
            .unwrap()
            .drain()
            .await;
        assert!(matches!(outcome, Ok(processkit::Outcome::Exited(7))));
        assert!(
            finish_job(
                &runtime,
                &owner,
                record.id,
                &cancel,
                outcome,
                &ends,
                (out_sync, err_sync)
            )
            .await
            .is_err()
        );
        let unknown = runtime.store.lookup(record.id, &owner).await.unwrap();
        assert_eq!(unknown.state, JobState::Interrupted);
        for stream in [JobOutput::Stdout, JobOutput::Stderr] {
            let (bytes, _, eof) = runtime.store.read_output(&unknown, stream, 0).unwrap();
            assert!(!bytes.is_empty());
            assert!(!eof, "unflushed pump must not fabricate complete logs");
        }
        assert_eq!(
            crate::jobs::active_ids(&runtime.store.root).unwrap(),
            [record.id.to_string()]
        );
    }
}

#[tokio::test]
async fn pump_marker_requires_successful_flush_and_resets_on_further_write() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("raw");
    let file = tokio::fs::File::create(&path).await.unwrap();
    let ended = Arc::new(AtomicBool::new(false));
    let mut writer =
        CappedOutputWriter::new(file, processkit::CancellationToken::new(), ended.clone());
    writer.write_all(b"prefix").await.unwrap();
    assert!(!ended.load(Ordering::Acquire));
    writer.flush().await.unwrap();
    assert!(ended.load(Ordering::Acquire));
    writer.write_all(b"tail").await.unwrap();
    assert!(!ended.load(Ordering::Acquire));
    writer.flush().await.unwrap();
    assert!(ended.load(Ordering::Acquire));
    assert_eq!(fs::read(path).unwrap(), b"prefixtail");
}

#[tokio::test]
async fn cancel_between_claim_and_spawn_is_failed_and_second_job_stays_healthy() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let (_root, runtime, owner, record) = prepared_job(
        vec!["-c".into(), "printf forbidden > cancelled-marker".into()],
        cwd.path(),
    )
    .await;
    let id = record.id;
    let mut healthy = record.spec.clone();
    healthy.args = vec!["-c".into(), "printf healthy > second-marker; exit 0".into()];
    let cancel = runtime.shutdown.child_token();
    cancel.cancel();
    run_job(runtime.clone(), owner.clone(), record, cancel)
        .await
        .unwrap();
    let cancelled = runtime.store.lookup(id, &owner).await.unwrap();
    assert_eq!(cancelled.state, JobState::Failed);
    assert!(!cwd.path().join("cancelled-marker").exists());
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        assert_eq!(
            runtime.store.read_output(&cancelled, stream, 0).unwrap(),
            (vec![], 0, true)
        );
    }
    assert!(runtime.accepting.load(Ordering::Acquire));
    assert!(!runtime.shutdown.is_cancelled());
    let second = JobId::new();
    runtime.store.admit(second, &owner, &healthy).await.unwrap();
    let mut worker = JobWorker::start(runtime.clone());
    tokio::time::timeout(Duration::from_secs(10), async {
        while runtime.store.lookup(second, &owner).await.unwrap().state
            != (JobState::Exited { code: 0 })
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fs::read(cwd.path().join("second-marker")).unwrap(),
        b"healthy"
    );
    assert!(!runtime.shutdown.is_cancelled());
    runtime.shutdown.cancel();
    (&mut worker.task).await.unwrap().unwrap();
    assert!(runtime.unknown_permits.lock().unwrap().is_empty());
    assert_eq!(runtime.slots.available_permits(), MAX_ACTIVE_JOBS);
}

#[tokio::test]
async fn parent_exit_with_closed_stdio_descendant_cannot_publish_before_tree_shutdown() {
    if !crate::jobs::process_tests::native_containment_available() {
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    let (_root, runtime, owner, record) = prepared_job(
        vec![
            "-c".into(),
            "(trap '' TERM; echo ready > child.ready; exec sleep 300) </dev/null >/dev/null 2>&1 & echo $! > survivor.pid; while [ ! -f child.ready ]; do :; done; exit 7".into(),
        ],
        cwd.path(),
    )
    .await;
    let id = record.id;
    tokio::time::timeout(
        Duration::from_secs(10),
        run_job(
            runtime.clone(),
            owner.clone(),
            record,
            runtime.shutdown.child_token(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let pid: u32 = fs::read_to_string(cwd.path().join("survivor.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        !crate::jobs::process_tests::linux_process_is_running(pid),
        "descendant must be gone when terminal state is visible"
    );
    assert_eq!(
        runtime.store.lookup(id, &owner).await.unwrap().state,
        JobState::Exited { code: 7 }
    );
    assert!(
        crate::jobs::active_ids(&runtime.store.root)
            .unwrap()
            .is_empty(),
        "only confirmed group teardown permits update"
    );
}
