use super::*;
use russh_sftp::server::Handler;
use std::sync::Arc;

async fn fixture(owner: &str) -> (tempfile::TempDir, SftpSession) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let session = SftpSession::new(&temp.path().join("jobs"), owner, permit).unwrap();
    (temp, session)
}

#[tokio::test]
async fn transfer_paths_are_private_and_reject_traversal_and_symlinks() {
    use std::os::unix::fs::symlink;
    let (temp, session) = fixture(&"a".repeat(64)).await;
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"secret").unwrap();
    symlink(&outside, session.root.join("escape")).unwrap();
    assert_eq!(
        session.resolve("../outside", false).await,
        Err(StatusCode::PermissionDenied)
    );
    assert_eq!(
        session.resolve("escape", false).await,
        Err(StatusCode::PermissionDenied)
    );
    assert!(session.resolve("normal.txt", true).await.is_ok());
    std::fs::hard_link(&outside, session.root.join("hardlink")).unwrap();
    assert_eq!(
        session.resolve("hardlink", false).await,
        Err(StatusCode::PermissionDenied)
    );
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let other = SftpSession::new(&temp.path().join("jobs"), &"b".repeat(64), permit).unwrap();
    assert_ne!(session.root, other.root);
    assert_eq!(
        other.resolve("normal.txt", false).await,
        Err(StatusCode::NoSuchFile)
    );
}

#[tokio::test]
async fn transfer_supports_writes_and_enforces_size_limit() {
    let (_temp, mut session) = fixture(&"c".repeat(64)).await;
    let handle = session
        .open(
            1,
            "file.txt".into(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await
        .unwrap()
        .handle;
    session
        .write(2, handle.clone(), 4, b"tail".to_vec())
        .await
        .unwrap();
    session
        .write(3, handle.clone(), 0, b"head".to_vec())
        .await
        .unwrap();
    session
        .write(4, handle.clone(), 0, b"H".to_vec())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(session.root.join("file.txt")).unwrap(),
        b"Headtail"
    );
    assert!(matches!(
        session.write(5, handle, MAX_TRANSFER_BYTES, vec![1]).await,
        Err(StatusCode::Failure)
    ));
}

#[tokio::test]
async fn transfer_reopen_preserves_contents_and_access_flags() {
    let (_temp, mut session) = fixture(&"d".repeat(64)).await;
    let flags = OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE;
    let handle = session
        .open(1, "data".into(), flags, FileAttributes::default())
        .await
        .unwrap()
        .handle;
    session
        .write(2, handle.clone(), 0, b"contents".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        session.read(3, handle.clone(), 0, 8).await,
        Err(StatusCode::Failure)
    ));
    assert!(
        session
            .open(4, "data".into(), flags, FileAttributes::default())
            .await
            .is_err()
    );
    session.close(5, handle).await.unwrap();
    let handle = session
        .open(6, "data".into(), OpenFlags::READ, FileAttributes::default())
        .await
        .unwrap()
        .handle;
    assert_eq!(
        session.read(7, handle.clone(), 0, 8).await.unwrap().data,
        b"contents"
    );
    assert!(matches!(
        session.write(8, handle.clone(), 0, vec![0]).await,
        Err(StatusCode::Failure)
    ));
    session.close(9, handle).await.unwrap();
    session.remove(10, "data".into()).await.unwrap();
    assert!(!session.root.join("data").exists());
}

#[tokio::test]
async fn transfer_roots_refuse_insecure_existing_directories_without_hardening() {
    use std::os::unix::fs::PermissionsExt;
    let (temp, session) = fixture(&"e".repeat(64)).await;
    let transfers = temp.path().join("transfers");
    std::fs::set_permissions(&transfers, std::fs::Permissions::from_mode(0o755)).unwrap();
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    assert!(SftpSession::new(&temp.path().join("jobs"), &"f".repeat(64), permit).is_err());
    assert_eq!(
        session.resolve("data", true).await,
        Err(StatusCode::PermissionDenied)
    );
    assert_eq!(
        std::fs::metadata(transfers).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!temp.path().join("transfers").join("f".repeat(64)).exists());
}
