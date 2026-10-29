use super::*;
use std::io::Write;

#[cfg(unix)]
#[test]
fn update_lock_drop_releases_fork_shared_open_file_description() {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let lease = acquire_update_lock(root.path()).unwrap();
    // Duplicated descriptors share one flock; closing the original without
    // LOCK_UN would leave the lock held until the duplicate closed.
    let inherited = lease.try_clone().unwrap();
    drop(lease);
    let replacement = acquire_update_lock(root.path()).unwrap();
    drop(replacement);
    drop(inherited);
}

use apalis_core::backend::WorkerFilter;

pub(super) async fn fixture() -> (tempfile::TempDir, JobStore) {
    let root = tempfile::tempdir().unwrap();
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();
    let store = JobStore::initialize_fresh(jobs).await.unwrap();
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

    assert!(JobStore::open(&jobs).await.is_err());
    assert!(!jobs.join("jobs.db").exists());
    fs::write(jobs.join("runner.lock"), b"runner evidence").unwrap();
    restrict_private_path(&jobs.join("runner.lock"), false).unwrap();
    assert!(JobStore::open(&jobs).await.is_err());
    assert!(JobStore::initialize_fresh(&jobs).await.is_err());
    assert!(!jobs.join("jobs.db").exists());
    assert_eq!(
        fs::read(jobs.join("runner.lock")).unwrap(),
        b"runner evidence"
    );

    // All mutations below are confined to this disposable fresh fixture.
    fs::remove_file(jobs.join("runner.lock")).unwrap();
    let store = JobStore::initialize_fresh(&jobs).await.unwrap();
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
    assert!(JobStore::open(&jobs).await.is_err());
    assert!(JobStore::initialize_fresh(&jobs).await.is_err());
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
        let store = JobStore::open(&root).await?;
        let runner = store.acquire_runner()?;
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

pub(super) fn sample() -> JobSpec {
    JobSpec {
        program: "echo".into(),
        args: vec!["hello".into()],
        cwd: None,
        source_sha256: "a".repeat(64),
    }
}
pub(super) fn owner() -> String {
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
    assert_eq!((store.admit(id, &owner(), &sample()).await.unwrap()).id, id);
    assert_eq!((store.admit(id, &owner(), &sample()).await.unwrap()).id, id);
    let mut conflict = sample();
    conflict.args.push("again".into());
    assert!(store.admit(id, &owner(), &conflict).await.is_err());
    conflict = sample();
    conflict.source_sha256 = "d".repeat(64);
    assert!(store.admit(id, &owner(), &conflict).await.is_err());
    assert!(store.admit(id, &"c".repeat(64), &sample()).await.is_err());
    assert!(store.lookup(id, &"c".repeat(64)).await.is_err());
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
async fn native_queued_cancel_is_terminal_without_process_or_output() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    assert!(store.cancel_pending(id, &"c".repeat(64)).await.is_err());
    let canceled = store.cancel_pending(id, &owner()).await.unwrap();
    assert_eq!(canceled.state, JobState::Failed);
    assert!(!canceled.started);
    assert_eq!(
        store.read_output(&canceled, JobOutput::Stdout, 0).unwrap(),
        (Vec::new(), 0, true)
    );
    assert!(active_ids(&store.root).unwrap().is_empty());
    assert!(store.cancel_pending(id, &owner()).await.is_err());
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
    let store = JobStore::open(root).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("PRAGMA synchronous")
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn canonical_ulid_is_enforced_during_serde_and_private_roots_fail_closed() {
    let (temp, store) = fixture().await;
    let id = JobId::new();
    assert!(JobId::parse("../root").is_err());
    assert!(
        serde_json::from_str::<JobId>(&format!("\"{}\"", id.to_string().to_lowercase())).is_err()
    );
    let bad = temp.path().join("public");
    fs::create_dir(&bad).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(JobStore::open(&bad).await.is_err());
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
    assert!(JobStore::open(&jobs).await.is_err());
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
    assert!(JobStore::open(&jobs).await.is_err());
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
async fn fifo_output_fails_closed_on_read_and_update_without_global_admission_scan() {
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
            .read_fixture_output(id, &owner(), JobOutput::Stdout, 0)
            .await
            .is_err()
    );
    // Admission checks its own indexed identity, not every unrelated output file.
    store
        .admit(JobId::new(), &owner(), &sample())
        .await
        .unwrap();
}

#[tokio::test]
async fn fresh_initialization_refuses_existing_store_and_upgrade_open_preserves_identity() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    let expected = store.admit(id, &owner(), &sample()).await.unwrap();
    let root = store.root.clone();
    store.close().await;
    let original = fs::read(root.join("jobs.db")).unwrap();
    assert!(JobStore::initialize_fresh(&root).await.is_err());
    assert_eq!(fs::read(root.join("jobs.db")).unwrap(), original);
    let reopened = JobStore::open(&root).await.unwrap();
    assert_eq!(reopened.lookup(id, &owner()).await.unwrap(), expected);
    assert_eq!(
        (reopened.admit(id, &owner(), &sample()).await.unwrap()).id,
        id
    );
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
    assert!(JobStore::open(&jobs).await.is_err());
    assert!(JobStore::initialize_fresh(&jobs).await.is_err());
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
    let error = JobStore::open(&root).await.unwrap_err();
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

#[tokio::test]
async fn native_list_is_owned_bounded_and_paginated_without_lifecycle_copies() {
    let (_temp, store) = fixture().await;
    let mut own_ids = Vec::new();
    for _ in 0..33 {
        let id = JobId::new();
        store.admit(id, &owner(), &sample()).await.unwrap();
        own_ids.push(id.to_string());
    }
    store
        .admit(JobId::new(), &"f".repeat(64), &sample())
        .await
        .unwrap();
    let first = store.list(&owner(), 1, None).await.unwrap();
    let second = store.list(&owner(), 2, None).await.unwrap();
    assert_eq!(first.len(), 32);
    assert_eq!(second.len(), 1);
    let mut actual: Vec<_> = first
        .into_iter()
        .chain(second)
        .map(|j| j.id.to_string())
        .collect();
    actual.sort();
    own_ids.sort();
    assert_eq!(actual, own_ids);
    assert_eq!(
        store
            .list(&owner(), 1, Some("Pending"))
            .await
            .unwrap()
            .len(),
        32
    );
    assert!(
        store
            .list(&owner(), 1, Some("Done"))
            .await
            .unwrap()
            .is_empty()
    );
    for page in [0, 129] {
        assert!(store.list(&owner(), page, None).await.is_err());
    }
    assert!(store.list(&owner(), 1, Some("unknown")).await.is_err());
}

#[tokio::test]
async fn old_sqlite_schema_is_preserved_and_rejected_without_migration() {
    for version in [1, 2, 3] {
        let (_temp, store) = fixture().await;
        sqlx::query("UPDATE DurableMeta SET version=?")
            .bind(version)
            .execute(&store.pool)
            .await
            .unwrap();
        let root = store.root.clone();
        store.close().await;
        let original = fs::read(root.join("jobs.db")).unwrap();
        assert!(JobStore::open(&root).await.is_err());
        assert!(JobStore::initialize_fresh(&root).await.is_err());
        assert!(active_ids(&root).is_err());
        assert_eq!(fs::read(root.join("jobs.db")).unwrap(), original);
    }
}

impl JobStore {
    pub(super) async fn read_fixture_output(
        &self,
        id: JobId,
        owner: &str,
        stream: JobOutput,
        offset: u64,
    ) -> io::Result<(Vec<u8>, u64, bool)> {
        self.read_output(&self.lookup(id, owner).await?, stream, offset)
    }
}

#[test]
fn ulid_rejects_aliases_overflow_uuid_and_paths() {
    for good in [
        "00000000000000000000000000",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ] {
        assert_eq!(JobId::parse(good).unwrap().to_string(), good);
    }
    for bad in [
        "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "01arz3ndektsv4rrffq69g5fav",
        "01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "01ARZ3NDEKTSV4RRFFQ69G5FAO",
        "01ARZ3NDEKTSV4RRFFQ69G5FA",
        "001ARZ3NDEKTSV4RRFFQ69G5FAV",
        "550e8400-e29b-41d4-a716-446655440000",
        "../01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        assert!(JobId::parse(bad).is_err(), "{bad}");
        assert!(serde_json::from_value::<JobId>(serde_json::json!(bad)).is_err());
    }
}

#[cfg(windows)]
#[test]
fn windows_new_upload_protects_only_valid_inherited_acl_and_rejects_hardlinks_before_change() {
    let temp = tempfile::tempdir().unwrap();
    restrict_private_path(temp.path(), true).unwrap();
    let valid = temp.path().join("new.upload");
    fs::write(&valid, b"disposable upload").unwrap();
    validate_windows_acl_contents(&valid, &fs::symlink_metadata(&valid).unwrap(), false).unwrap();
    secure_new_upload(&valid).unwrap();
    validate_private_path(&valid, false).unwrap();
    assert_eq!(fs::read(&valid).unwrap(), b"disposable upload");

    let linked = temp.path().join("linked.upload");
    fs::write(&linked, b"preserve bytes and inherited DACL").unwrap();
    fs::hard_link(&linked, temp.path().join("alias.upload")).unwrap();
    let metadata = fs::symlink_metadata(&linked).unwrap();
    validate_windows_acl_contents(&linked, &metadata, false).unwrap();
    assert!(
        validate_windows_acl(&linked, &metadata).is_err(),
        "fixture must have an unprotected inherited DACL"
    );
    assert!(secure_new_upload(&linked).is_err());
    assert!(
        validate_windows_acl(&linked, &fs::symlink_metadata(&linked).unwrap()).is_err(),
        "hardlink refusal must not protect/change the DACL"
    );
    assert_eq!(
        fs::read(&linked).unwrap(),
        b"preserve bytes and inherited DACL"
    );
}

#[tokio::test]
async fn native_orphan_requeue_and_result_projection() {
    use apalis_core::{backend::TaskResult, task::status::Status};
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    sqlx::query("INSERT INTO Workers(id,worker_type,storage_name,last_seen) VALUES('fixture-worker','hostlink-agent','SqliteStorage',0)")
        .execute(&store.pool).await.unwrap();
    let ids = vec![id.to_string()];
    assert_eq!(
        apalis_sqlite::queries::lock_tasks(&store.pool, &ids, "fixture-worker")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.lookup(id, &owner()).await.unwrap().state,
        JobState::Running
    );
    assert_eq!(
        apalis_sqlite::queries::reenqueue_orphaned(
            &store.pool,
            1,
            database::QUEUE,
            &WorkerFilter::Only("fixture-worker".into())
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        store.lookup(id, &owner()).await.unwrap().state,
        JobState::Prepared
    );
    assert_eq!(
        apalis_sqlite::queries::lock_tasks(&store.pool, &ids, "fixture-worker")
            .await
            .unwrap(),
        1
    );
    let result = TaskResult {
        task_id: id.to_string().parse().unwrap(),
        attempt: 2,
        status: Status::Done,
        result: Ok(serde_json::json!(7)),
    };
    assert_eq!(
        apalis_sqlite::queries::ack_tasks(&store.pool, &[&result], "fixture-worker")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.lookup(id, &owner()).await.unwrap().state,
        JobState::Exited { code: 7 }
    );
}

#[tokio::test]
async fn cancel_pending_requires_owner_and_prevents_native_lock() {
    let (_temp, store) = fixture().await;
    let id = JobId::new();
    store.admit(id, &owner(), &sample()).await.unwrap();
    assert_eq!(
        store
            .cancel_pending(id, &"c".repeat(64))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        store.cancel_pending(id, &owner()).await.unwrap().state,
        JobState::Failed
    );
    assert_eq!(
        apalis_sqlite::queries::lock_tasks(&store.pool, &[id.to_string()], "fixture-worker")
            .await
            .unwrap(),
        0
    );
    assert!(store.cancel_pending(id, &owner()).await.is_err());
}
