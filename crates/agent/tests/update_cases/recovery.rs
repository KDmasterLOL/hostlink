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
#[tokio::test]
async fn active_job_prevents_recovery_mutations_then_update_recovers_backup() {
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
    let _store = JobStore::initialize_fresh(&jobs).await.expect("job store");
    let id = started_job::queued(&jobs).await;
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(matches!(
        apply(&update).expect("defer while recovery is pending"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.clone()]
    ));
    assert!(!root.join("bin").exists());
    assert!(backup.join("hostlink-agent").is_file());

    started_job::completed(&jobs, &id).await;
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

#[test]
fn legacy_records_block_update_without_replacing_or_removing_existing_state() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    let legacy = jobs.join(ulid::Ulid::generate().to_string());
    fs::create_dir_all(&legacy).expect("legacy record directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [&jobs, &legacy] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private legacy directory");
        }
    }
    let record = legacy.join("record.json");
    let saved = br#"{"legacy":"requires explicit verified migration"}"#;
    fs::write(&record, saved).expect("legacy evidence");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600))
            .expect("private legacy record");
    }
    let error = apply(&request(&root, &archive, "2.0.0", digest))
        .expect_err("legacy state cannot imply an empty SQLite store");
    assert!(
        error.to_string().to_ascii_lowercase().contains("legacy"),
        "existing deployments need an actionable migration report: {error}"
    );
    assert_eq!(fs::read(&record).expect("preserved legacy evidence"), saved);
    assert!(!jobs.join("jobs.db").exists());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original Agent"),
        b"old installed Agent binary"
    );
}

#[tokio::test]
async fn unknown_legacy_output_blocks_update_without_modifying_existing_state() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("job root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private job root");
    }
    JobStore::initialize_fresh(&jobs)
        .await
        .expect("fresh SQLite store")
        .close()
        .await;
    // The new queue uses Apalis results, not HostLink output directories.
    // Any legacy output tree must be preserved and refused as unknown state.
    let orphan = jobs.join("outputs");
    fs::create_dir(&orphan).expect("legacy output evidence");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o700))
            .expect("private orphan output");
    }
    assert!(active_ids(&jobs).is_err(), "legacy output is unknown state");
    assert!(apply(&request(&root, &archive, "2.0.0", digest)).is_err());
    assert!(orphan.is_dir(), "unknown evidence must remain intact");
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original Agent"),
        b"old installed Agent binary"
    );
}

#[test]
fn empty_uninitialized_job_root_does_not_prove_update_safety() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("uninitialized job root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700))
            .expect("private uninitialized job root");
    }
    assert!(active_ids(&jobs).is_err());
    assert!(apply(&request(&root, &archive, "2.0.0", digest)).is_err());
    assert!(
        !jobs.join("jobs.db").exists(),
        "safety scan must not recreate lost state"
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original Agent"),
        b"old installed Agent binary"
    );
}
