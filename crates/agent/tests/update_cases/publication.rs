use super::*;

#[tokio::test]
async fn queued_apalis_task_survives_stopped_agent_update() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
    }
    JobStore::initialize_fresh(&jobs)
        .await
        .unwrap()
        .close()
        .await;
    let id = started_job::queued(&jobs).await;

    let update = request(&root, &archive, "2.0.0", digest);
    assert!(matches!(
        apply(&update).unwrap(),
        AgentUpdateOutcome::Installed { .. }
    ));
    let reopened = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(jobs.join("jobs.db"))
            .read_only(true),
    )
    .await
    .unwrap();
    let stored_id: String = sqlx::query_scalar("SELECT id FROM Jobs WHERE id=?")
        .bind(&id)
        .fetch_one(&reopened)
        .await
        .unwrap();
    assert_eq!(
        stored_id, id,
        "updater must leave native Apalis tasks untouched"
    );
    reopened.close().await;
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).unwrap(),
        b"new exact Agent binary"
    );
}

#[tokio::test]
async fn running_agent_lifetime_lock_blocks_update_before_publication() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
    }
    JobStore::initialize_fresh(&jobs)
        .await
        .unwrap()
        .close()
        .await;

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(jobs.join("runner.lock"))
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(jobs.join("runner.lock"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    lock.lock().unwrap();

    let update = request(&root, &archive, "2.0.0", digest);
    assert_eq!(
        apply(&update).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).unwrap(),
        b"old installed Agent binary"
    );
    lock.unlock().unwrap();
    assert!(matches!(
        apply(&update).unwrap(),
        AgentUpdateOutcome::Installed { .. }
    ));
}

#[test]
fn exact_package_updates_files_and_repeat_is_idempotent() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let request = request(&root, &archive, "2.0.0", digest.clone());

    assert_eq!(
        apply_empty_jobs(&request).expect("install package"),
        AgentUpdateOutcome::Installed {
            version: "2.0.0".to_owned(),
            archive_sha256: digest.clone(),
        }
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("installed binary"),
        b"new exact Agent binary"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("bin/hostlink-agent"))
            .expect("installed metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o100, 0);
        assert_eq!(mode & 0o022, 0, "group/world write bits must be clear");
    }
    assert_eq!(
        apply_empty_jobs(&request).expect("idempotent repeat"),
        AgentUpdateOutcome::AlreadyCurrent {
            version: "2.0.0".to_owned(),
            archive_sha256: digest,
        }
    );
}
#[test]
fn extracted_package_root_is_the_source_for_linux_publication() {
    let (_temp, root) = install_root();
    let executable = b"binary from self_update extracted package root";
    let (archive, digest) = package(&root, "2.1.0", executable);

    assert_eq!(
        apply_empty_jobs(&request(&root, &archive, "2.1.0", digest.clone()))
            .expect("publish validated extracted package"),
        AgentUpdateOutcome::Installed {
            version: "2.1.0".to_owned(),
            archive_sha256: digest.clone(),
        }
    );

    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("published executable"),
        executable,
        "the publisher must consume the member extracted beneath the package root"
    );
    let metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("install.json")).expect("published install metadata"),
    )
    .expect("valid install metadata");
    assert_eq!(metadata["target"], TARGET);
    assert_eq!(metadata["installed_version"], "2.1.0");
    assert_eq!(metadata["installed_package_sha256"], digest);
    assert_eq!(
        metadata["installed_files"]["hostlink-agent"],
        identity(executable)
    );
}
#[test]
fn self_update_move_all_restores_first_file_when_second_move_fails() {
    let temp = TempDir::new().expect("temporary publication fixture");
    let stash = temp.path().join("stash");
    fs::create_dir(&stash).expect("private same-volume stash");
    let first_source = temp.path().join("new-agent.exe");
    let missing_second_source = temp.path().join("missing-install.json");
    let first_destination = temp.path().join("hostlink-agent.exe");
    let second_destination = temp.path().join("install.json");
    fs::write(&first_source, b"new executable").expect("new executable");
    fs::write(&first_destination, b"old executable").expect("old executable");
    fs::write(&second_destination, b"old metadata").expect("old metadata");

    let mut moves = self_update::MoveAll::from_temp(&stash);
    moves
        .add(&first_source, &first_destination)
        .add(&missing_second_source, &second_destination);
    assert!(
        moves.commit().is_err(),
        "the missing second source must fail"
    );
    assert_eq!(
        fs::read(&first_destination).expect("first destination after rollback"),
        b"old executable"
    );
    assert_eq!(
        fs::read(&second_destination).expect("second destination after rollback"),
        b"old metadata"
    );
    assert!(
        fs::read_dir(&stash)
            .expect("stash inventory")
            .next()
            .is_none(),
        "library rollback must not leave displaced files behind"
    );
}

#[cfg(unix)]
#[test]
fn unsafe_executable_permissions_block_update() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let executable = root.join("bin/hostlink-agent");

    for unsafe_mode in [0o471, 0o722] {
        fs::set_permissions(&executable, fs::Permissions::from_mode(unsafe_mode))
            .expect("set unsafe executable permissions");
        let update = request(&root, &archive, "2.0.0", digest.clone());
        assert!(apply_empty_jobs(&update).is_err());
        assert_eq!(
            fs::read(&executable).expect("original executable remains"),
            b"old installed Agent binary"
        );
        assert_eq!(
            fs::metadata(&executable)
                .expect("executable metadata")
                .permissions()
                .mode()
                & 0o777,
            unsafe_mode
        );
    }
}
#[test]
fn tampered_installed_binary_blocks_update() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    fs::write(root.join("bin/hostlink-agent"), b"tampered").expect("tamper binary");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("tampered binary remains untouched"),
        b"tampered"
    );
}
