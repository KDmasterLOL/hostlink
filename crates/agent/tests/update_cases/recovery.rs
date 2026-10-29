use super::*;

#[test]
fn updater_leaves_unrecognized_jobs_files_intact() {
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
    assert!(matches!(
        apply(&update).unwrap(),
        AgentUpdateOutcome::Installed { .. }
    ));
    assert_eq!(
        fs::read(jobs.join("not-a-job-record")).unwrap(),
        b"unknown state"
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated binary"),
        b"new exact Agent binary"
    );
}
#[tokio::test]
async fn pending_apalis_task_survives_recovery_and_update() {
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
    // The updater waits for the Agent process, not for pending Apalis jobs.
    // A stopped Agent can update while Apalis retains work for the next start.
    assert!(matches!(
        apply(&update).expect("recover and update"),
        AgentUpdateOutcome::Installed { .. }
    ));
    let reopened = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(jobs.join("jobs.db"))
            .read_only(true),
    )
    .await
    .unwrap();
    let saved: String = sqlx::query_scalar("SELECT id FROM Jobs WHERE id=?")
        .bind(&id)
        .fetch_one(&reopened)
        .await
        .unwrap();
    assert_eq!(saved, id);
    reopened.close().await;
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
fn legacy_jobs_are_not_interpreted_or_deleted_by_updater() {
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
    assert!(
        matches!(
            apply(&request(&root, &archive, "2.0.0", digest)).unwrap(),
            AgentUpdateOutcome::Installed { .. }
        ),
        "updater does not need to inspect Apalis job files"
    );
    assert_eq!(fs::read(&record).expect("preserved legacy evidence"), saved);
    assert!(!jobs.join("jobs.db").exists());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated Agent"),
        b"new exact Agent binary"
    );
}

#[tokio::test]
async fn unrelated_files_are_left_untouched_by_updater() {
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
    // An unrelated directory must be left alone, not interpreted as jobs state.
    let orphan = jobs.join("outputs");
    fs::create_dir(&orphan).expect("legacy output evidence");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o700))
            .expect("private orphan output");
    }
    assert!(matches!(
        apply(&request(&root, &archive, "2.0.0", digest)).unwrap(),
        AgentUpdateOutcome::Installed { .. }
    ));
    assert!(orphan.is_dir(), "unknown evidence must remain intact");
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated Agent"),
        b"new exact Agent binary"
    );
}

#[test]
fn updater_does_not_initialize_missing_apalis_database() {
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
    assert!(matches!(
        apply(&request(&root, &archive, "2.0.0", digest)).unwrap(),
        AgentUpdateOutcome::Installed { .. }
    ));
    assert!(
        !jobs.join("jobs.db").exists(),
        "updater must not create Apalis state"
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated Agent"),
        b"new exact Agent binary"
    );
}
