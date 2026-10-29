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
