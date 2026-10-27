use super::*;

#[cfg(unix)]
#[tokio::test]
async fn rejects_parent_paths_and_symlinks_outside_root() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private temporary root");
    let jobs = temp.path().join("jobs");
    tokio::fs::create_dir(&jobs)
        .await
        .expect("create jobs root");
    let artifacts =
        crate::durable::ArtifactStore::open(&jobs, &"d".repeat(64)).expect("controller artifacts");
    let root = artifacts.upload_root();
    let outside = temp.path().join("outside");
    tokio::fs::write(&outside, b"secret")
        .await
        .expect("write outside file");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join(format!("{}.upload", "a".repeat(64))))
        .expect("create symlink");

    let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("SFTP slot");
    let session = SftpSession::new(artifacts, permit);
    assert_eq!(
        session.resolve("../outside", false).await,
        Err(StatusCode::PermissionDenied)
    );
    #[cfg(unix)]
    assert_eq!(
        session.resolve("escape", false).await,
        Err(StatusCode::PermissionDenied)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_upload_growth_past_the_per_file_limit() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private temporary root");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    let artifacts =
        crate::durable::ArtifactStore::open(&jobs, &"e".repeat(64)).expect("controller artifacts");
    let upload_path = artifacts
        .upload_root()
        .join(format!("{}.upload", "f".repeat(64)));
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(upload_path)
        .await
        .expect("create sparse upload fixture");
    file.set_len(crate::durable::MAX_ARTIFACT_BYTES)
        .await
        .expect("set exact maximum length");
    let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("SFTP slot");
    let mut session = SftpSession::new(artifacts, permit);
    session.files.insert(
        "h".into(),
        OpenFile {
            file,
            write_ranges: Vec::new(),
            writable: true,
        },
    );
    assert!(matches!(
        russh_sftp::server::Handler::write(
            &mut session,
            1,
            "h".into(),
            crate::durable::MAX_ARTIFACT_BYTES,
            vec![0],
        )
        .await,
        Err(StatusCode::Failure)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn accepts_pipelined_out_of_order_non_overlapping_writes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private temporary root");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    let artifacts =
        crate::durable::ArtifactStore::open(&jobs, &"b".repeat(64)).expect("controller artifacts");
    let file_path = artifacts
        .upload_root()
        .join(format!("{}.upload", "c".repeat(64)));
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_path.clone())
        .await
        .expect("create upload");
    let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("SFTP slot");
    let mut session = SftpSession::new(artifacts, permit);
    session.files.insert(
        "h".into(),
        OpenFile {
            file,
            write_ranges: Vec::new(),
            writable: true,
        },
    );

    // SFTP clients pipeline WRITE packets; their offsets can arrive out of order.
    russh_sftp::server::Handler::write(&mut session, 1, "h".into(), 4, b"tail".to_vec())
        .await
        .expect("accept later-offset packet before earlier packet");
    russh_sftp::server::Handler::write(&mut session, 2, "h".into(), 0, b"head".to_vec())
        .await
        .expect("accept preceding non-overlapping packet");
    assert_eq!(
        tokio::fs::read(file_path.clone())
            .await
            .expect("read upload"),
        b"headtail"
    );

    assert!(matches!(
        russh_sftp::server::Handler::write(&mut session, 3, "h".into(), 2, b"bad".to_vec()).await,
        Err(StatusCode::Failure)
    ));
    assert_eq!(
        tokio::fs::read(file_path)
            .await
            .expect("read upload after overlap rejection"),
        b"headtail"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn total_upload_and_sealed_file_count_is_bounded() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private temporary root");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    let artifacts =
        crate::durable::ArtifactStore::open(&jobs, &"9".repeat(64)).expect("controller artifacts");
    for index in 0..crate::durable::MAX_ARTIFACTS_PER_CONTROLLER - 1 {
        let path = artifacts.upload_root().join(format!("{index:064x}.upload"));
        std::fs::write(&path, b"upload").expect("seed upload");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private upload");
    }
    let sealed = artifacts
        .sealed_root()
        .join(format!("{:064x}.program", u64::MAX));
    std::fs::write(&sealed, b"sealed").expect("seed sealed artifact");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o500))
        .expect("protected sealed artifact");
    let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("SFTP slot");
    let mut session = SftpSession::new(artifacts, permit);
    assert!(matches!(
        russh_sftp::server::Handler::open(
            &mut session,
            1,
            format!("{}.upload", "a".repeat(64)),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await,
        Err(StatusCode::Failure)
    ));
}
