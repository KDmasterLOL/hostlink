use super::*;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use std::{fs, io::Write, path::Path};

fn open_test_lock(path: &Path) -> io::Result<File> {
    PrivateDir::open(std::path::absolute(path.parent().unwrap())?)
        .and_then(|directory| {
            directory.open_file_with(
                path.file_name().unwrap(),
                OpenOptions {
                    access: FileAccess::ReadWrite,
                    creation: FileCreation::OpenOrCreate,
                    ..OpenOptions::default()
                },
            )
        })
        .map_err(io::Error::other)?
        .try_clone_std()
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, PrivateDir) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("private");
    let directory = PrivateDir::ensure(&root).unwrap();
    (temp, root, directory)
}

#[cfg(unix)]
#[test]
fn std_clone_retains_acquired_object_after_path_replacement() {
    use std::io::{Read, Seek, SeekFrom};

    let (_temp, root, directory) = fixture();
    let mut file = directory.create("file").unwrap();
    file.write_all(b"original").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    fs::rename(root.join("file"), root.join("retained")).unwrap();
    directory
        .create("file")
        .unwrap()
        .write_all(b"replacement")
        .unwrap();

    let mut first = file.try_clone_std().unwrap();
    let mut second = file.try_clone_std().unwrap();
    drop(file);
    let mut prefix = [0; 4];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"orig");
    let mut suffix = String::new();
    second.read_to_string(&mut suffix).unwrap();
    assert_eq!(suffix, "inal");
    assert_eq!(fs::read(root.join("file")).unwrap(), b"replacement");
}

#[cfg(unix)]
#[tokio::test]
async fn sftp_metadata_uses_verified_file_clones() {
    use crate::sftp::SftpSession;
    use russh_sftp::{
        protocol::{FileAttributes, OpenFlags},
        server::Handler,
    };
    use std::sync::Arc;

    let (_temp, root, _) = fixture();
    let slot = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let mut session = SftpSession::new(&root.join("jobs"), &"a".repeat(64), slot).unwrap();
    let handle = session
        .open(
            1,
            "file".into(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await
        .unwrap()
        .handle;
    session
        .write(2, handle.clone(), 0, b"metadata".to_vec())
        .await
        .unwrap();
    assert_eq!(
        session.stat(3, "file".into()).await.unwrap().attrs.size,
        Some(8)
    );
    assert_eq!(
        session.lstat(4, "file".into()).await.unwrap().attrs.size,
        Some(8)
    );
    assert_eq!(
        session.fstat(5, handle.clone()).await.unwrap().attrs.size,
        Some(8)
    );
    session.close(6, handle).await.unwrap();
}

#[test]
fn lock_reopen_preserves_contents_and_serializes_independent_handles() {
    let (_temp, root, _) = fixture();
    let path = root.join("update.lock");
    let mut first = open_test_lock(&path).unwrap();
    first.write_all(b"preserve").unwrap();
    private_fs::verify(&first).unwrap();
    first.try_lock().unwrap();
    let second = open_test_lock(&path).unwrap();
    assert!(second.try_lock().is_err());
    first.unlock().unwrap();
    second.try_lock().unwrap();
    second.unlock().unwrap();
    assert_eq!(fs::read(path).unwrap(), b"preserve");
}

#[test]
fn lock_creation_race_opens_one_private_object() {
    let (_temp, root, directory) = fixture();
    let path = root.join("runner.lock");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                open_test_lock(&path).unwrap()
            })
        })
        .collect();
    let files: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    files[0].try_lock().unwrap();
    for file in &files[1..] {
        private_fs::verify(file).unwrap();
        assert!(file.try_lock().is_err());
    }
    assert_eq!(directory.entries().unwrap().len(), 1);
    files[0].unlock().unwrap();
}

#[test]
fn lock_serializes_processes() {
    let (_temp, root, _) = fixture();
    let path = root.join("update.lock");
    let file = open_test_lock(&path).unwrap();
    file.try_lock().unwrap();
    for locked in [true, false] {
        if !locked {
            file.unlock().unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "private_fs::tests::lock_child", "--nocapture"])
            .env("HOSTLINK_PRIVATE_LOCK_TEST_PATH", &path)
            .env("HOSTLINK_PRIVATE_LOCK_TEST_HELD", locked.to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn lock_child() {
    let Some(path) = std::env::var_os("HOSTLINK_PRIVATE_LOCK_TEST_PATH") else {
        return;
    };
    let held = std::env::var("HOSTLINK_PRIVATE_LOCK_TEST_HELD").unwrap() == "true";
    let file = open_test_lock(Path::new(&path)).unwrap();
    assert_eq!(file.try_lock().is_err(), held);
}

#[test]
fn private_files_and_locks_reject_hardlinks() {
    let (_temp, root, directory) = fixture();
    directory
        .create("file")
        .unwrap()
        .write_all(b"contents")
        .unwrap();
    let file = directory.open_file("file").unwrap();
    fs::hard_link(root.join("file"), root.join("alias")).unwrap();
    assert!(file.verify().is_err());
    assert!(file.try_clone_std().is_err());
    assert!(directory.open_file("file").is_err());
    assert!(open_test_lock(&root.join("file")).is_err());
    assert_eq!(fs::read(root.join("file")).unwrap(), b"contents");
}

#[cfg(unix)]
#[test]
fn private_acquisition_rejects_links_and_permissions_without_repair() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_temp, root, directory) = fixture();
    directory
        .create("file")
        .unwrap()
        .write_all(b"unchanged")
        .unwrap();
    let path = root.join("file");
    symlink(&path, root.join("link")).unwrap();
    assert!(directory.open_file("link").is_err());
    assert!(open_test_lock(&root.join("link")).is_err());
    let file = directory.open_file("file").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(file.try_clone_std().is_err());
    assert!(directory.open_file("file").is_err());
    assert!(open_test_lock(&path).is_err());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let alias = root.with_extension("alias");
    symlink(&root, &alias).unwrap();
    assert!(PrivateDir::open(&alias).is_err());
    assert!(open_test_lock(&alias.join("new.lock")).is_err());
    fs::remove_file(alias).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PrivateDir::open(&root).is_err());
    assert!(PrivateDir::ensure(&root).is_err());
    assert!(open_test_lock(&root.join("new.lock")).is_err());
    assert!(!root.join("new.lock").exists());
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(fs::read(path).unwrap(), b"unchanged");
}
