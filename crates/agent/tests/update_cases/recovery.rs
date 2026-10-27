use super::*;

#[test]
fn unknown_job_store_entry_fails_closed() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
    }
    fs::write(jobs.join("not-a-job-record"), b"unknown state").expect("unknown entry");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(apply(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}
#[test]
fn active_job_prevents_recovery_mutations_then_update_recovers_backup() {
    let (_temp, root) = install_root();
    let old_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("old metadata"))
            .expect("valid old metadata");
    let backup_name = format!("backup-1.0.0-{}", "a".repeat(64));
    let updates = root.join(".updates");
    fs::create_dir(&updates).expect("updates directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&updates, fs::Permissions::from_mode(0o700))
            .expect("private updates directory");
    }
    let backup = updates.join(&backup_name);
    fs::rename(root.join("bin"), &backup).expect("simulate interrupted rename");
    fs::write(
        updates.join("publication.json"),
        serde_json::to_vec(&json!({
            "format": 1,
            "backup": backup_name,
            "old_metadata": old_metadata,
        }))
        .expect("journal JSON"),
    )
    .expect("write recovery journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            updates.join("publication.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private recovery journal");
    }

    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
    }
    let store = JobStore::open(&jobs).expect("job store");
    let id = JobId::new();
    let owner = "1".repeat(64);
    store
        .admit(
            id,
            &owner,
            &JobSpec {
                program: "true".to_owned(),
                args: Vec::new(),
                cwd: None,
                source_sha256: "2".repeat(64),
            },
        )
        .expect("admit active job");
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(matches!(
        apply(&update).expect("defer while recovery is pending"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.to_string()]
    ));
    assert!(!root.join("bin").exists());
    assert!(backup.join("hostlink-agent").is_file());

    store
        .transition(id, &owner, JobState::Prepared, JobState::Failed)
        .expect("job reaches terminal state");
    assert!(matches!(
        apply(&update).expect("recover and update"),
        AgentUpdateOutcome::Installed { .. }
    ));
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated binary"),
        b"new exact Agent binary"
    );
}
#[test]
fn recovery_restores_old_install_after_simulated_interrupted_publication() {
    let (_temp, root) = install_root();
    let old_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("old metadata"))
            .expect("valid old metadata");
    let backup_name = format!("backup-1.0.0-{}", "a".repeat(64));
    let updates = root.join(".updates");
    fs::create_dir(&updates).expect("updates directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&updates, fs::Permissions::from_mode(0o700))
            .expect("private updates directory");
    }
    let backup = updates.join(&backup_name);
    fs::rename(root.join("bin"), &backup).expect("simulate crash after backup rename");
    let journal = updates.join("publication.json");
    fs::write(
        &journal,
        serde_json::to_vec(&json!({
            "format": 1,
            "backup": backup_name,
            "old_metadata": old_metadata,
        }))
        .expect("journal JSON"),
    )
    .expect("write recovery journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))
            .expect("private recovery journal");
    }

    let (archive, _) = package(&root, "2.0.0", b"new exact Agent binary");
    let bad_digest = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&bad_digest).is_err());

    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("restored old executable"),
        b"old installed Agent binary"
    );
    let restored_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("restored metadata"))
            .expect("valid restored metadata");
    assert_eq!(restored_metadata, old_metadata);
    assert!(!backup.exists());
    assert!(!journal.exists());
}
