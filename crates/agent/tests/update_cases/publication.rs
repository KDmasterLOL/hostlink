use super::*;

#[tokio::test]
async fn active_job_blocks_update_despite_unrelated_empty_jobs_directory() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    let unrelated_empty_jobs = root.join("unrelated-empty-jobs");
    fs::create_dir(&unrelated_empty_jobs).expect("unrelated empty jobs directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
        fs::set_permissions(&unrelated_empty_jobs, fs::Permissions::from_mode(0o700))
            .expect("private unrelated jobs directory");
    }
    let store = JobStore::initialize_fresh(&jobs).await.expect("job store");
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
        .await
        .expect("admit prepared job");

    let update = request(&root, &archive, "2.0.0", digest);
    assert!(
        fs::read_dir(&unrelated_empty_jobs)
            .expect("unrelated empty jobs directory")
            .next()
            .is_none()
    );
    assert_eq!(
        apply(&update).expect("defer update"),
        AgentUpdateOutcome::DeferredActiveJobs {
            job_ids: vec![id.to_string()],
        }
    );
    assert_eq!(
        active_ids(&jobs).expect("job stays active"),
        vec![id.to_string()]
    );
    started_job::started(&jobs, &store, id, &owner).await;
    assert!(matches!(
        apply(&update).expect("running job defers update"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.to_string()]
    ));
    // A native Apalis Running task remains active until the worker recovers
    // it. Recovery may replay it, but an updater must still defer.
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
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
