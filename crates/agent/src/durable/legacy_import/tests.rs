use super::*;
use snapshot::{STREAMS, read_file, write_file};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    stage: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        restrict_private_path(&parent, true).unwrap();
        let source = parent.join("snapshot");
        fs::create_dir(&source).unwrap();
        restrict_private_path(&source, true).unwrap();
        write_file(&source.join(UPDATE_LOCK_FILE), b"").unwrap();
        let root = source.join("jobs");
        fs::create_dir(&root).unwrap();
        restrict_private_path(&root, true).unwrap();
        Self {
            _temp: temp,
            root,
            stage: parent.join("stage"),
        }
    }

    fn job(&self, state: JobState, spools: [bool; 2]) -> JobRecord {
        let id = JobId::new();
        // Exact 4570a45 JSON field names and enum representation. Whitespace
        // and trailing newline deliberately differ from runtime serialization.
        let spec = JobSpec {
            program: "never-execute-legacy-import-fixture".into(),
            args: vec!["старый аргумент".into(), "a\nb".into()],
            cwd: Some(PathBuf::from("private-work")),
            source_sha256: "a".repeat(64),
        };
        let record = JobRecord {
            version: 1,
            id,
            controller_key_sha256: "b".repeat(64),
            request_sha256: format!("{:x}", Sha256::digest(spec.serialized().unwrap())),
            spec,
            state,
        };
        let dir = self.root.join(id.to_string());
        fs::create_dir(&dir).unwrap();
        restrict_private_path(&dir, true).unwrap();
        let mut raw = serde_json::to_vec_pretty(&record).unwrap();
        raw.push(b'\n');
        write_file(&dir.join("record.json"), &raw).unwrap();
        write_file(&dir.join("state.lock"), b"").unwrap();
        for (index, name) in STREAMS.iter().enumerate() {
            if spools[index] {
                write_file(&dir.join(name), &binary_output()).unwrap();
            }
        }
        record
    }

    async fn stage(&self) -> io::Error {
        stage_legacy_snapshot(&self.root, &self.stage)
            .await
            .unwrap_err()
    }
}

fn binary_output() -> Vec<u8> {
    (0..=255)
        .cycle()
        .take(MAX_OUTPUT_CHUNK_BYTES + 313)
        .collect()
}

#[tokio::test]
async fn all_legacy_states_preserve_exact_identity_bytes_and_uncertainty() {
    let f = Fixture::new();
    for state in [
        JobState::Prepared,
        JobState::Running,
        JobState::Interrupted,
        JobState::Exited { code: -713 },
        JobState::Failed,
    ] {
        f.job(state, [true, true]);
    }
    // Failed never establishes whether a process ran. Preserve every spool
    // combination, including a single stream, without claiming execution.
    for spools in [[false, false], [true, false], [false, true]] {
        f.job(JobState::Failed, spools);
    }
    let before = Snapshot::read(&f.root).unwrap();
    let error = f.stage().await;
    assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
    assert!(error.to_string().contains("publication blocked"));
    assert_eq!(Snapshot::read(&f.root).unwrap(), before);
    staging::verify(&f.stage, &before).await.unwrap();
    assert!(DurableStore::open(f.stage.join("store")).await.is_err());
    assert!(DurableStore::open(f.root.clone()).await.is_err());
    assert!(!f.root.join("jobs.db").exists());
    assert!(!f.root.join("runner.lock").exists());
    let root = f.stage.join("store");
    let pool = database::connect(&root, true).await.unwrap();
    let store = DurableStore::attach(root, pool).await.unwrap();
    for source in &before.records {
        let original = &source.record;
        assert_eq!(
            store
                .lookup(original.id, &original.controller_key_sha256)
                .await
                .unwrap(),
            source.mapped()
        );
        assert!(store.lookup(original.id, &"c".repeat(64)).await.is_err());
        // Real production raw output API; all byte values cross chunk boundary.
        for (index, stream) in [JobOutput::Stdout, JobOutput::Stderr]
            .into_iter()
            .enumerate()
        {
            if source.streams[index].is_some() {
                let (bytes, next, eof) = store
                    .read_output(original.id, &original.controller_key_sha256, stream, 0)
                    .await
                    .unwrap();
                assert_eq!(bytes, binary_output()[..MAX_OUTPUT_CHUNK_BYTES]);
                assert_eq!(next, MAX_OUTPUT_CHUNK_BYTES as u64);
                assert!(!eof);
                let (tail, end, eof) = store
                    .read_output(original.id, &original.controller_key_sha256, stream, next)
                    .await
                    .unwrap();
                assert_eq!(tail, binary_output()[MAX_OUTPUT_CHUNK_BYTES..]);
                assert_eq!(end, binary_output().len() as u64);
                assert_eq!(eof, !source.mapped().state.blocks_update());
                assert!(
                    store
                        .read_output(
                            original.id,
                            &original.controller_key_sha256,
                            stream,
                            end + 1
                        )
                        .await
                        .is_err()
                );
            } else {
                assert_eq!(
                    store
                        .read_output(original.id, &original.controller_key_sha256, stream, 0)
                        .await
                        .unwrap(),
                    (vec![], 0, true)
                );
                assert!(
                    store
                        .read_output(original.id, &original.controller_key_sha256, stream, 1)
                        .await
                        .is_err()
                );
            }
        }
    }
    store.close().await;
}

#[tokio::test]
async fn completed_restart_lost_ack_is_repeat_safe_and_detects_changed_source() {
    let f = Fixture::new();
    let record = f.job(JobState::Exited { code: 27 }, [true, true]);
    assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
    let before = snapshot::hash_file(&f.stage.join("store/jobs.db"), 16 * 1024 * 1024).unwrap();
    assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        snapshot::hash_file(&f.stage.join("store/jobs.db"), 16 * 1024 * 1024).unwrap(),
        before
    );
    let path = f.root.join(record.id.to_string()).join("stdout.bin");
    fs::write(path, b"changed").unwrap();
    assert_eq!(f.stage().await.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        snapshot::hash_file(&f.stage.join("store/jobs.db"), 16 * 1024 * 1024).unwrap(),
        before
    );
}

#[tokio::test]
async fn malformed_identity_version_owner_and_request_sha_reject_before_staging() {
    for field in [
        "version",
        "id",
        "controller_key_sha256",
        "request_sha256",
        "spec",
        "unknown",
    ] {
        let f = Fixture::new();
        let record = f.job(JobState::Prepared, [false, false]);
        let path = f.root.join(record.id.to_string()).join("record.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json[field] = match field {
            "version" => 99.into(),
            "id" => JobId::new().to_string().into(),
            "controller_key_sha256" => "B".repeat(64).into(),
            "request_sha256" => "0".repeat(64).into(),
            "spec" => serde_json::json!({"program": "forged"}),
            _ => true.into(),
        };
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            f.stage().await.kind(),
            io::ErrorKind::InvalidData,
            "{field}"
        );
        assert!(!f.stage.exists());
        assert_eq!(fs::read(&path).unwrap(), serde_json::to_vec(&json).unwrap());
    }
}

#[tokio::test]
async fn torn_records_missing_exited_spools_unknown_entries_and_uuid_aliases_reject() {
    for fault in ["torn", "missing", "alias", "unknown", "oversized"] {
        let f = Fixture::new();
        let record = f.job(JobState::Exited { code: 9 }, [true, true]);
        let dir = f.root.join(record.id.to_string());
        match fault {
            "torn" => fs::write(dir.join("record.json"), b"{torn").unwrap(),
            "missing" => fs::remove_file(dir.join("stderr.bin")).unwrap(),
            "alias" => {
                let alias = f.root.join(format!("{{{}}}", record.id));
                fs::create_dir(&alias).unwrap();
                restrict_private_path(&alias, true).unwrap();
            }
            "unknown" => write_file(&dir.join("extra"), b"retain").unwrap(),
            _ => OpenOptions::new()
                .write(true)
                .open(dir.join("stdout.bin"))
                .unwrap()
                .set_len(MAX_JOB_OUTPUT_BYTES + 1)
                .unwrap(),
        }
        assert!(
            f.stage().await.kind() != io::ErrorKind::Unsupported,
            "{fault}"
        );
        assert!(!f.stage.exists());
        assert!(dir.exists());
    }
}

#[tokio::test]
async fn update_state_runner_and_stage_contention_never_waits_or_publishes() {
    for which in ["update", "state", "runner", "stage"] {
        let f = Fixture::new();
        let record = f.job(JobState::Prepared, [false, false]);
        let path = match which {
            "update" => f.root.parent().unwrap().join(UPDATE_LOCK_FILE),
            "state" => f.root.join(record.id.to_string()).join("state.lock"),
            "runner" => {
                let path = f.root.join("runner.lock");
                write_file(&path, b"").unwrap();
                path
            }
            _ => {
                assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
                f.stage.join("stage.lock")
            }
        };
        let lease = lock_existing(&path).unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), f.stage())
            .await
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{which}: {error}");
        drop(lease);
        assert!(!f.root.join("jobs.db").exists());
    }
}

#[tokio::test]
async fn crash_boundaries_are_preserved_and_never_silently_resumed() {
    for boundary in [
        "reservation",
        "journal",
        "database",
        "sink",
        "built",
        "unverified",
    ] {
        let f = Fixture::new();
        f.job(JobState::Prepared, [false, false]);
        let source = Snapshot::read(&f.root).unwrap();
        if matches!(boundary, "built" | "unverified") {
            assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
            fs::remove_file(f.stage.join("verified")).unwrap();
            if boundary == "built" {
                fs::remove_file(f.stage.join("built")).unwrap();
            }
        } else {
            fs::create_dir(&f.stage).unwrap();
            restrict_private_path(&f.stage, true).unwrap();
            if boundary != "reservation" {
                write_file(&f.stage.join("stage.lock"), b"").unwrap();
                let journal = Journal {
                    format: 1,
                    legacy_source: LEGACY_SOURCE.into(),
                    snapshot_sha256: source.digest().unwrap(),
                    records: source.records.len(),
                    publication: "blocked".into(),
                    blocker: BLOCKER.into(),
                };
                write_file(
                    &f.stage.join(JOURNAL),
                    &serde_json::to_vec(&journal).unwrap(),
                )
                .unwrap();
            }
            if matches!(boundary, "database" | "sink") {
                let root = f.stage.join("store");
                fs::create_dir(&root).unwrap();
                restrict_private_path(&root, true).unwrap();
                let pool = database::initialize_fresh(&root).await.unwrap();
                sqlx::query("UPDATE DurableMeta SET version=?")
                    .bind(QUARANTINE_VERSION)
                    .execute(&pool)
                    .await
                    .unwrap();
                if boundary == "sink" {
                    use apalis_core::task::builder::TaskBuilder;
                    use futures::SinkExt;
                    let mut backend = apalis_sqlite::SqliteStorage::<JobRecord>::new(&pool);
                    backend
                        .send(
                            TaskBuilder::new(
                                serde_json::to_vec(&source.records[0].mapped()).unwrap(),
                            )
                            .idempotency_key(source.records[0].record.id.to_string())
                            .max_attempts(1)
                            .build(),
                        )
                        .await
                        .unwrap();
                }
                pool.close().await;
                assert!(DurableStore::open(root).await.is_err());
            }
        }
        let journal = fs::read(f.stage.join(JOURNAL)).ok();
        assert_ne!(
            f.stage().await.kind(),
            io::ErrorKind::Unsupported,
            "{boundary}"
        );
        assert_eq!(Snapshot::read(&f.root).unwrap(), source);
        assert_eq!(fs::read(f.stage.join(JOURNAL)).ok(), journal);
        assert!(f.stage.exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn private_permissions_symlinks_hardlinks_and_fifo_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for fault in [
        "public",
        "symlink",
        "directory-link",
        "hardlink",
        "ancestor-link",
        "fifo",
    ] {
        let f = Fixture::new();
        let record = f.job(JobState::Exited { code: 5 }, [true, true]);
        let dir = f.root.join(record.id.to_string());
        let output = dir.join("stdout.bin");
        match fault {
            "public" => fs::set_permissions(&output, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                fs::remove_file(&output).unwrap();
                symlink(dir.join("stderr.bin"), &output).unwrap();
            }
            "directory-link" => {
                let moved = f.root.parent().unwrap().join("outside");
                fs::rename(&dir, &moved).unwrap();
                symlink(moved, &dir).unwrap();
            }
            "hardlink" => fs::hard_link(&output, f.root.parent().unwrap().join("linked")).unwrap(),
            "ancestor-link" => {
                let alias = f.stage.parent().unwrap().join("alias");
                symlink(f.root.parent().unwrap(), &alias).unwrap();
                assert!(
                    stage_legacy_snapshot(&alias.join("jobs"), &f.stage)
                        .await
                        .is_err()
                );
                assert!(!f.stage.exists());
                continue;
            }
            _ => {
                fs::remove_file(&output).unwrap();
                let path = std::ffi::CString::new(output.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: path is NUL-terminated and valid for this call.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        assert_ne!(
            f.stage().await.kind(),
            io::ErrorKind::Unsupported,
            "{fault}"
        );
        assert!(!f.stage.exists());
    }
}

#[tokio::test]
async fn verified_stage_tampering_is_rejected_without_source_changes() {
    for fault in [
        "output",
        "claim",
        "tombstone",
        "attempts",
        "quarantine",
        "journal",
    ] {
        let f = Fixture::new();
        let record = f.job(JobState::Exited { code: 31 }, [true, true]);
        let source = Snapshot::read(&f.root).unwrap();
        assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
        if fault == "output" {
            fs::write(
                f.stage
                    .join("store/outputs")
                    .join(record.id.to_string())
                    .join("stdout.bin"),
                b"changed",
            )
            .unwrap();
        } else if fault == "journal" {
            fs::write(f.stage.join(JOURNAL), b"{torn").unwrap();
        } else {
            let pool = database::connect(&f.stage.join("store"), false)
                .await
                .unwrap();
            let query = match fault {
                "claim" => "UPDATE StartedClaims SET owner='forged'",
                "tombstone" => "DELETE FROM LegacyImportSources",
                "attempts" => "UPDATE Jobs SET attempts=0",
                _ => "UPDATE DurableMeta SET version=1",
            };
            sqlx::query(query).execute(&pool).await.unwrap();
            pool.close().await;
        }
        assert_ne!(
            f.stage().await.kind(),
            io::ErrorKind::Unsupported,
            "{fault}"
        );
        assert_eq!(Snapshot::read(&f.root).unwrap(), source);
        assert_eq!(
            read_file(
                &f.root.join(record.id.to_string()).join("record.json"),
                MAX_RECORD_BYTES as u64
            )
            .unwrap(),
            source.records[0].raw
        );
    }
}

#[tokio::test]
async fn moving_a_claim_to_an_originally_prepared_uuid_is_not_valid_provenance() {
    let f = Fixture::new();
    let prepared = f.job(JobState::Prepared, [false, false]);
    let running = f.job(JobState::Running, [true, true]);
    assert_eq!(f.stage().await.kind(), io::ErrorKind::Unsupported);
    let pool = database::connect(&f.stage.join("store"), false)
        .await
        .unwrap();
    // Both map to Interrupted; tuple and total count alone cannot distinguish
    // a real old reservation from a fabricated one on an unstarted request.
    sqlx::query("DELETE FROM StartedClaims WHERE job_id=?")
        .bind(running.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO StartedClaims(job_id,task_id,owner,request_sha256) SELECT idempotency_key,id,?,? FROM Jobs WHERE idempotency_key=?")
        .bind(&prepared.controller_key_sha256).bind(&prepared.request_sha256)
        .bind(prepared.id.to_string()).execute(&pool).await.unwrap();
    pool.close().await;
    assert_eq!(f.stage().await.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn rejected_destination_and_missing_source_lock_never_change_source() {
    let f = Fixture::new();
    f.job(JobState::Prepared, [false, false]);
    let before = Snapshot::read(&f.root).unwrap();
    for stage in [&f.root, &f.root.join("inside"), f.root.parent().unwrap()] {
        assert_eq!(
            stage_legacy_snapshot(&f.root, stage)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(Snapshot::read(&f.root).unwrap(), before);
    }
    fs::remove_file(f.root.parent().unwrap().join(UPDATE_LOCK_FILE)).unwrap();
    assert_eq!(f.stage().await.kind(), io::ErrorKind::NotFound);
    assert!(!f.stage.exists());
    assert!(!f.root.parent().unwrap().join(UPDATE_LOCK_FILE).exists());
}

#[tokio::test]
async fn only_prepared_may_lack_the_old_transition_lock() {
    for state in [
        JobState::Prepared,
        JobState::Running,
        JobState::Interrupted,
        JobState::Failed,
        JobState::Exited { code: 4 },
    ] {
        let f = Fixture::new();
        let record = f.job(state, [true, true]);
        let lock = f.root.join(record.id.to_string()).join("state.lock");
        fs::remove_file(&lock).unwrap();
        let error = f.stage().await;
        if state == JobState::Prepared {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        } else {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert!(!f.stage.exists());
        }
        assert!(!lock.exists());
    }
}
