use super::*;
use apalis_core::backend::WorkerFilter;

async fn fixture() -> (tempfile::TempDir, DurableStore) {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();
    let store = DurableStore::initialize_fresh(jobs).await.unwrap();
    (root, store)
}

#[test]
fn a_missing_database_never_proves_update_safety() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();
    assert!(active_ids(&jobs).is_err());
}

#[tokio::test]
async fn runtime_never_recreates_a_missing_database_or_runner_only_root() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();

    assert!(DurableStore::open(&jobs).await.is_err());
    assert!(!jobs.join("jobs.db").exists());
    fs::write(jobs.join("runner.lock"), b"runner evidence").unwrap();
    restrict_private_path(&jobs.join("runner.lock"), false).unwrap();
    assert!(DurableStore::open(&jobs).await.is_err());
    assert!(DurableStore::initialize_fresh(&jobs).await.is_err());
    assert!(!jobs.join("jobs.db").exists());
    assert_eq!(
        fs::read(jobs.join("runner.lock")).unwrap(),
        b"runner evidence"
    );

    // All mutations below are confined to this disposable fresh fixture.
    fs::remove_file(jobs.join("runner.lock")).unwrap();
    let store = DurableStore::initialize_fresh(&jobs).await.unwrap();
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    let spool = store.output_path(id, JobOutput::Stdout);
    let mut output = open_output_append(&spool).unwrap();
    output.write_all(&[0, 255, 7]).unwrap();
    output.sync_all().unwrap();
    drop(output);
    store.close().await;
    for name in ["jobs.db", "jobs.db-wal", "jobs.db-shm"] {
        match fs::remove_file(jobs.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && name != "jobs.db" => {}
            Err(error) => panic!("remove disposable closed database: {error}"),
        }
    }
    assert!(DurableStore::open(&jobs).await.is_err());
    assert!(DurableStore::initialize_fresh(&jobs).await.is_err());
    assert!(active_ids(&jobs).is_err());
    assert!(!jobs.join("jobs.db").exists());
    assert_eq!(fs::read(spool).unwrap(), [0, 255, 7]);
}

#[tokio::test]
async fn registered_replacement_can_open_and_recover_while_updater_holds_lock() {
    use std::sync::mpsc;
    let (_temp, store) = fixture().await;
    let root = store.root.clone();
    store.close().await;
    let install_root = root.parent().unwrap().to_path_buf();

    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (unlock_tx, unlock_rx) = mpsc::sync_channel::<()>(1);
    let updater = std::thread::spawn(move || {
        let _lock = acquire_update_lock(&install_root).unwrap();
        locked_tx.send(()).unwrap();
        unlock_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    });
    locked_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let candidate = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let store = DurableStore::open(&root).await?;
        let runner = store.acquire_runner()?;
        store.recover_nonterminal().await?;
        drop(runner);
        store.close().await;
        Ok::<(), io::Error>(())
    })
    .await;
    unlock_tx.send(()).unwrap();
    updater.join().unwrap();
    assert!(
        matches!(candidate, Ok(Ok(()))),
        "registered replacement cannot wait for the updater-held lock during health"
    );
}

fn sample() -> JobSpec {
    JobSpec {
        program: "echo".into(),
        args: vec!["hello".into()],
        cwd: None,
        source_sha256: "a".repeat(64),
    }
}
fn owner() -> String {
    "b".repeat(64)
}

#[tokio::test]
async fn artifact_seal_preserves_content_and_controller_ownership() {
    let (_temp, store) = fixture().await;
    let artifacts = store.artifacts(&owner()).unwrap();
    let bytes = b"sealed executable fixture";
    let digest = format!("{:x}", Sha256::digest(bytes));
    let name = format!("{digest}.upload");
    let upload = artifacts.upload_root().join(&name);
    fs::write(&upload, bytes).unwrap();
    restrict_private_path(&upload, false).unwrap();
    assert!(
        artifacts
            .seal(&name, &digest, (bytes.len() + 1) as u64)
            .is_err()
    );
    assert!(
        artifacts
            .seal(&name, &"c".repeat(64), bytes.len() as u64)
            .is_err()
    );
    let sealed = artifacts.seal(&name, &digest, bytes.len() as u64).unwrap();
    assert_eq!(fs::read(&sealed).unwrap(), bytes);
    assert_eq!(
        artifacts.seal(&name, &digest, bytes.len() as u64).unwrap(),
        sealed
    );
    assert!(active_ids(&store.root).unwrap().is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(sealed).unwrap().permissions().mode() & 0o777,
            0o500
        );
    }
    assert_ne!(
        store.artifacts(&"c".repeat(64)).unwrap().upload_root(),
        artifacts.upload_root()
    );
}

#[tokio::test]
async fn same_identity_is_idempotent_and_owner_or_spec_conflicts_fail() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    assert!(matches!(
        store.admit(id, &owner(), &sample()).await.unwrap(),
        Admission::Created(_)
    ));
    assert!(matches!(
        store.admit(id, &owner(), &sample()).await.unwrap(),
        Admission::Existing(_)
    ));
    let mut conflict = sample();
    conflict.args.push("again".into());
    assert!(store.admit(id, &owner(), &conflict).await.is_err());
    conflict = sample();
    conflict.source_sha256 = "d".repeat(64);
    assert!(store.admit(id, &owner(), &conflict).await.is_err());
    assert!(store.admit(id, &"c".repeat(64), &sample()).await.is_err());
    assert!(store.lookup(id, &"c".repeat(64)).await.is_err());
    assert!(store.claim_start(id, &"c".repeat(64)).await.is_err());
    assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM Jobs")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        1
    );
    assert!(!store.output_dir(id).join("record.json").exists());
}

#[tokio::test]
async fn terminal_nonzero_exit_does_not_block_but_interrupted_stays_unknown() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    assert!(
        store
            .transition(id, &owner(), JobState::Prepared, JobState::Running)
            .await
            .is_err()
    );
    store.claim_start(id, &owner()).await.unwrap();
    assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        open_output_append(&store.output_path(id, stream))
            .unwrap()
            .sync_all()
            .unwrap();
    }
    store
        .transition(
            id,
            &owner(),
            JobState::Running,
            JobState::Exited { code: 7 },
        )
        .await
        .unwrap();
    assert!(active_ids(&store.root).unwrap().is_empty());
    assert!(store.claim_start(id, &owner()).await.is_err());
    assert!(
        store
            .transition(
                id,
                &owner(),
                JobState::Exited { code: 7 },
                JobState::Prepared
            )
            .await
            .is_err()
    );
    let next = JobId::new();
    store.admit(next, &owner(), &sample()).await.unwrap();
    store.recover_nonterminal().await.unwrap();
    assert_eq!(
        store.lookup(next, &owner()).await.unwrap().state,
        JobState::Interrupted
    );
    assert_eq!(active_ids(&store.root).unwrap(), vec![next.to_string()]);
    assert!(
        store
            .transition(next, &owner(), JobState::Interrupted, JobState::Failed)
            .await
            .is_err()
    );
    assert!(store.claim_start(next, &owner()).await.is_err());
}

#[tokio::test]
async fn actual_apalis_orphan_requeue_cannot_replay_started_command_even_after_restart() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    store.claim_start(id, &owner()).await.unwrap();
    // This is the real upstream query that ignores max_attempts for Pending.
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,last_seen) VALUES('crashed-worker','hostlink-agent-v1','SqliteStorage',0)").execute(&store.pool).await.unwrap();
    sqlx::query("UPDATE Jobs SET lock_at=0,lock_by='crashed-worker' WHERE idempotency_key=?")
        .bind(id.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
    let affected = apalis_sqlite::queries::reenqueue_orphaned(
        &store.pool,
        1,
        database::QUEUE,
        &WorkerFilter::None,
    )
    .await
    .unwrap();
    assert_eq!(affected, 1);
    let status: String = sqlx::query_scalar("SELECT status FROM Jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(status, "Pending");
    assert!(store.claim_start(id, &owner()).await.is_err());
    assert!(active_ids(&store.root).is_err());
    let root = store.root.clone();
    store.close().await;
    let reopened = DurableStore::open(root).await.unwrap();
    reopened.recover_nonterminal().await.unwrap();
    assert_eq!(
        reopened.lookup(id, &owner()).await.unwrap().state,
        JobState::Interrupted
    );
    assert!(matches!(
        reopened.admit(id, &owner(), &sample()).await.unwrap(),
        Admission::Existing(_)
    ));
    assert!(reopened.claim_start(id, &owner()).await.is_err());
    assert_eq!(active_ids(&reopened.root).unwrap(), vec![id.to_string()]);
}

#[tokio::test]
async fn lost_admission_and_claim_ack_never_grants_another_attempt() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    let _lost_admission = store.admit(id, &owner(), &sample()).await.unwrap();
    assert!(matches!(
        store.admit(id, &owner(), &sample()).await.unwrap(),
        Admission::Existing(_)
    ));
    let _lost_claim = store.claim_start(id, &owner()).await.unwrap();
    let root = store.root.clone();
    store.close().await;
    let store = DurableStore::open(root).await.unwrap();
    assert!(store.claim_start(id, &owner()).await.is_err());
    store.recover_nonterminal().await.unwrap();
    assert_eq!(
        store.lookup(id, &owner()).await.unwrap().state,
        JobState::Interrupted
    );
    assert!(store.claim_start(id, &owner()).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_independent_pools_admit_and_claim_exactly_once() {
    let (_temp, store) = fixture().await;
    let second = DurableStore::open(&store.root).await.unwrap();
    let id = JobId::new();
    let owner = owner();
    let spec = sample();
    let (a, b) = tokio::join!(
        store.admit(id, &owner, &spec),
        second.admit(id, &owner, &spec)
    );
    assert!(matches!(
        (a.unwrap(), b.unwrap()),
        (Admission::Created(_), Admission::Existing(_))
            | (Admission::Existing(_), Admission::Created(_))
    ));
    let (a, b) = tokio::join!(
        store.claim_start(id, &owner),
        second.claim_start(id, &owner)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}

#[tokio::test]
async fn full_wal_is_verified_on_replaced_connections_and_reopen() {
    let (_temp, store) = fixture().await;
    for _ in 0..3 {
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA synchronous")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            "wal"
        );
        conn.close().await.unwrap();
    }
    let root = store.root.clone();
    store.close().await;
    let store = DurableStore::open(root).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("PRAGMA synchronous")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn raw_output_offsets_ownership_and_unknown_eof_are_preserved() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    assert!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 1)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 0)
            .await
            .unwrap(),
        (Vec::new(), 0, false)
    );
    store.claim_start(id, &owner()).await.unwrap();
    let mut f = open_output_append(&store.output_path(id, JobOutput::Stdout)).unwrap();
    f.write_all(&[0, 255, 128, 7]).unwrap();
    f.sync_all().unwrap();
    assert_eq!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 1)
            .await
            .unwrap(),
        (vec![255, 128, 7], 4, false)
    );
    assert!(
        store
            .read_output(id, &"c".repeat(64), JobOutput::Stdout, 0)
            .await
            .is_err()
    );
    store.recover_nonterminal().await.unwrap();
    assert_eq!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 4)
            .await
            .unwrap(),
        (vec![], 4, false)
    );
    assert!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 5)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn canonical_uuid_is_enforced_during_serde_and_private_roots_fail_closed() {
    let (temp, store) = fixture().await;
    let id = JobId::new();
    assert!(JobId::parse("../root").is_err());
    assert!(
        serde_json::from_str::<JobId>(&format!("\"{}\"", id.to_string().to_uppercase())).is_err()
    );
    let bad = temp.path().join("public");
    fs::create_dir(&bad).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(DurableStore::open(&bad).await.is_err());
    }
    let lease = store.acquire_runner().unwrap();
    assert!(store.acquire_runner().is_err());
    drop(lease);
    assert!(store.acquire_runner().is_ok());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_private_database_hardlink_fails_closed() {
    let (temp, store) = fixture().await;
    let jobs = store.root.clone();
    store.close().await;
    let linked = temp.path().join("outside-jobs.db");
    fs::hard_link(jobs.join("jobs.db"), &linked).unwrap();
    assert!(validate_private_path(&jobs.join("jobs.db"), false).is_err());
    assert!(DurableStore::open(&jobs).await.is_err());
    assert!(active_ids(&jobs).is_err());
}

#[cfg(windows)]
#[tokio::test]
async fn windows_sqlite_sidecar_hardlink_is_rejected_before_acl_hardening() {
    let (temp, store) = fixture().await;
    let jobs = store.root.clone();
    store.close().await;
    // All of these paths belong to this disposable test root. A protected
    // ACL alone does not make an NTFS hardlink safe to modify.
    let wal = jobs.join("jobs.db-wal");
    fs::write(&wal, b"disposable-sidecar").unwrap();
    restrict_private_path(&wal, false).unwrap();
    fs::hard_link(&wal, temp.path().join("linked-sidecar")).unwrap();
    assert!(database::secure_sidecars(&jobs).is_err());
    assert!(DurableStore::open(&jobs).await.is_err());
}

#[tokio::test]
async fn tampered_payload_claim_or_apalis_queue_prevents_updates_and_execution() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    sqlx::query("UPDATE Jobs SET job=x'62726f6b656e'")
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(active_ids(&store.root).is_err());
    assert!(store.claim_start(id, &owner()).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_database_or_output_directory_is_never_resolved() {
    use std::os::unix::fs::symlink;
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    symlink(".", store.output_dir(id)).unwrap();
    assert!(active_ids(&store.root).is_err());
    assert!(store.admit(id, &owner(), &sample()).await.is_err());
}

#[tokio::test]
async fn oversized_record_is_rejected_before_admission_and_corrupt_blob_is_bounded() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    let mut spec = sample();
    spec.args = vec!["x".repeat(MAX_RECORD_BYTES - 160)];
    assert!(spec.serialized().is_ok());
    assert!(store.admit(id, &owner(), &spec).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM Jobs")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        0
    );
    store.admit(id, &owner(), &sample()).await.unwrap();
    sqlx::query("UPDATE Jobs SET job=zeroblob(?)")
        .bind((MAX_RECORD_BYTES + 1) as i64)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(store.lookup(id, &owner()).await.is_err());
    assert!(active_ids(&store.root).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn fifo_output_fails_closed_without_blocking_admission_or_updater() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    let path = store.output_path(id, JobOutput::Stdout);
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a live NUL-terminated path; mode is an ordinary private FIFO mode.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(validate_private_path(&path, false).is_err());
    let root = store.root.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || sender.send(active_ids(&root)).unwrap());
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .is_err()
    );
    handle.join().unwrap();
    assert!(
        store
            .admit(JobId::new(), &owner(), &sample())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_exited_output_is_an_error_and_never_a_fabricated_eof() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    store.claim_start(id, &owner()).await.unwrap();
    store
        .transition(
            id,
            &owner(),
            JobState::Running,
            JobState::Exited { code: 0 },
        )
        .await
        .unwrap();
    assert!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 0)
            .await
            .is_err()
    );
    assert!(active_ids(&store.root).is_err());
}

#[tokio::test]
async fn claimed_failed_output_loss_is_never_reported_as_empty_eof() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    store.claim_start(id, &owner()).await.unwrap();
    for stream in [JobOutput::Stdout, JobOutput::Stderr] {
        let mut output = open_output_append(&store.output_path(id, stream)).unwrap();
        output.write_all(b"partial output").unwrap();
        output.sync_all().unwrap();
    }
    store
        .transition(id, &owner(), JobState::Running, JobState::Failed)
        .await
        .unwrap();
    fs::remove_file(store.output_path(id, JobOutput::Stdout)).unwrap();
    assert!(
        store
            .read_output(id, &owner(), JobOutput::Stdout, 0)
            .await
            .is_err(),
        "a claimed Failed job must not falsely return empty EOF"
    );
    assert!(
        active_ids(&store.root).is_err(),
        "lost claimed output must block update safety checks"
    );
}

#[tokio::test]
async fn fresh_initialization_refuses_existing_store_and_upgrade_open_preserves_identity() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    let Admission::Created(expected) = store.admit(id, &owner(), &sample()).await.unwrap() else {
        panic!("new request")
    };
    let root = store.root.clone();
    store.close().await;
    let original = fs::read(root.join("jobs.db")).unwrap();
    assert!(DurableStore::initialize_fresh(&root).await.is_err());
    assert_eq!(fs::read(root.join("jobs.db")).unwrap(), original);
    let reopened = DurableStore::open(&root).await.unwrap();
    assert_eq!(reopened.lookup(id, &owner()).await.unwrap(), expected);
    assert!(matches!(
        reopened.admit(id, &owner(), &sample()).await.unwrap(),
        Admission::Existing(_)
    ));
    let mut changed = sample();
    changed.args.push("different".into());
    assert!(reopened.admit(id, &owner(), &changed).await.is_err());
}

#[tokio::test]
async fn runtime_rejects_torn_empty_database_without_running_schema_creation() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();
    let database = jobs.join("jobs.db");
    fs::write(&database, []).unwrap();
    restrict_private_path(&database, false).unwrap();
    fs::create_dir(jobs.join("outputs")).unwrap();
    restrict_private_path(&jobs.join("outputs"), true).unwrap();
    assert!(DurableStore::open(&jobs).await.is_err());
    assert!(DurableStore::initialize_fresh(&jobs).await.is_err());
    assert_eq!(fs::metadata(database).unwrap().len(), 0);
    assert!(!jobs.join("jobs.db-wal").exists());
    assert!(!jobs.join("jobs.db-shm").exists());
    assert!(active_ids(&jobs).is_err());
}

#[tokio::test]
async fn runtime_validates_migration_history_without_reapplying_missing_migrations() {
    let (_temp, store) = fixture().await;
    let expected: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM _sqlx_migrations WHERE version=(SELECT min(version) FROM _sqlx_migrations)",
    )
    .execute(&store.pool)
    .await
    .unwrap();
    let root = store.root.clone();
    store.close().await;
    let original = fs::read(root.join("jobs.db")).unwrap();
    let error = DurableStore::open(&root).await.unwrap_err();
    assert!(error.to_string().contains("migration history"), "{error}");
    assert_eq!(fs::read(root.join("jobs.db")).unwrap(), original);
    use sqlx::Connection;
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(root.join("jobs.db"))
            .read_only(true),
    )
    .await
    .unwrap();
    let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        actual,
        expected - 1,
        "runtime opening must not repair the ledger"
    );
    connection.close().await.unwrap();
}
