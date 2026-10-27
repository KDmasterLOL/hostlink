use super::*;

fn fixture() -> (tempfile::TempDir, JobStore) {
    let root = tempfile::tempdir().expect("private fixture parent");
    restrict_private_path(root.path(), true).unwrap();
    let jobs = root.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    restrict_private_path(&jobs, true).unwrap();
    let store = JobStore::open(jobs).unwrap();
    (root, store)
}

fn sample() -> JobSpec {
    JobSpec {
        program: "echo".into(),
        args: vec!["hello".into()],
        cwd: None,
        source_sha256: "a".repeat(64),
    }
}

#[test]
fn artifact_seal_checks_content_and_is_idempotent_outside_job_scan() {
    let (_temp, store) = fixture();
    let owner = "b".repeat(64);
    let artifacts = store.artifacts(&owner).unwrap();
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
            fs::metadata(&sealed).unwrap().permissions().mode() & 0o777,
            0o500
        );
    }
}

#[test]
fn same_identity_is_idempotent_and_conflict_fails() {
    let (_temp, store) = fixture();
    let id = JobId::new();
    let owner = "b".repeat(64);
    assert!(matches!(
        store.admit(id, &owner, &sample()).unwrap(),
        Admission::Created(_)
    ));
    assert!(matches!(
        store.admit(id, &owner, &sample()).unwrap(),
        Admission::Existing(_)
    ));
    let mut conflict = sample();
    conflict.args.push("again".into());
    assert!(store.admit(id, &owner, &conflict).is_err());
    assert!(store.lookup(id, &"c".repeat(64)).is_err());
    assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
}

#[test]
fn missing_output_rejects_nonzero_offset() {
    let (_temp, store) = fixture();
    let id = JobId::new();
    let owner = "b".repeat(64);
    store.admit(id, &owner, &sample()).unwrap();
    assert!(store.read_output(id, &owner, JobOutput::Stdout, 1).is_err());
    assert_eq!(
        store.read_output(id, &owner, JobOutput::Stdout, 0).unwrap(),
        (Vec::new(), 0, false)
    );
}

#[test]
fn terminal_jobs_no_longer_block_but_interrupted_jobs_do() {
    let (_temp, store) = fixture();
    let id = JobId::new();
    let owner = "b".repeat(64);
    store.admit(id, &owner, &sample()).unwrap();
    store
        .transition(id, &owner, JobState::Prepared, JobState::Running)
        .unwrap();
    assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
    store
        .transition(id, &owner, JobState::Running, JobState::Exited { code: 7 })
        .unwrap();
    assert!(active_ids(&store.root).unwrap().is_empty());
    assert!(
        store
            .transition(id, &owner, JobState::Exited { code: 7 }, JobState::Running)
            .is_err()
    );

    let next_id = JobId::new();
    store.admit(next_id, &owner, &sample()).unwrap();
    store
        .transition(next_id, &owner, JobState::Prepared, JobState::Interrupted)
        .unwrap();
    assert_eq!(active_ids(&store.root).unwrap(), vec![next_id.to_string()]);
}

#[test]
fn private_root_and_corrupt_record_fail_closed() {
    let (temp, store) = fixture();
    let id = JobId::new();
    let owner = "b".repeat(64);
    store.admit(id, &owner, &sample()).unwrap();
    fs::write(store.job_dir(id).join("record.json"), b"broken").unwrap();
    assert!(active_ids(&store.root).is_err());
    assert!(JobId::parse("../root").is_err());
    assert!(JobId::parse(&id.to_string().to_uppercase()).is_err());
    let bad_root = temp.path().join("public");
    fs::create_dir(&bad_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad_root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(JobStore::open(&bad_root).is_err());
    }
}

#[test]
fn torn_admission_prevents_update_and_no_retry_is_inferred() {
    let (_temp, store) = fixture();
    let id = JobId::new();
    let orphan = store.job_dir(id);
    fs::create_dir(&orphan).unwrap();
    restrict_private_path(&orphan, true).unwrap();
    // A crash after reserving an ID but before committing the record is UNKNOWN.
    assert!(active_ids(&store.root).is_err());
    assert!(store.admit(id, &"b".repeat(64), &sample()).is_err());
    assert!(!orphan.join("record.json").exists());
}

#[test]
fn concurrent_admission_never_creates_two_records() {
    let (_temp, store) = fixture();
    let shared = std::sync::Arc::new(store);
    let id = JobId::new();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = shared.clone();
        handles.push(std::thread::spawn(move || {
            store.admit(id, &"b".repeat(64), &sample())
        }));
    }
    let mut created = 0;
    for handle in handles {
        if let Ok(Admission::Created(_)) = handle.join().unwrap() {
            created += 1;
        }
    }
    assert_eq!(
        created, 1,
        "atomic UUID reservation must have exactly one winner"
    );
    let authenticated = shared.lookup(id, &"b".repeat(64)).unwrap();
    assert_eq!(authenticated.state, JobState::Prepared);
    assert_eq!(active_ids(&shared.root).unwrap(), vec![id.to_string()]);
}

#[cfg(unix)]
#[test]
fn symlink_job_directory_is_never_resolved() {
    use std::os::unix::fs::symlink;
    let (_temp, store) = fixture();
    let id = JobId::new();
    symlink(".", store.job_dir(id)).unwrap();
    assert!(active_ids(&store.root).is_err());
}
