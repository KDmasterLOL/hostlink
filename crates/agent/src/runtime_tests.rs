use super::*;
use std::fs;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("Agent");
    let dir = PrivateDir::ensure(&root).unwrap();
    dir.create_dir("bin").unwrap();
    dir.create_dir("jobs").unwrap();
    let exe = root.join("bin").join(crate::package::EXECUTABLE_NAME);
    fs::write(&exe, b"test executable").unwrap();
    (temp, root, exe)
}

#[test]
fn installed_runner_uses_updater_lock_and_excludes_another_holder() {
    let (_temp, root, exe) = fixture();
    let jobs = root.join("jobs");
    let selected = runner_root(&exe, &root, &jobs).unwrap();
    assert_eq!(selected.join("runner.lock"), jobs.join("runner.lock"));
    let open_lock = || {
        PrivateDir::open(&selected)
            .unwrap()
            .open_file_with(
                "runner.lock",
                OpenOptions {
                    access: FileAccess::ReadWrite,
                    creation: FileCreation::OpenOrCreate,
                    ..OpenOptions::default()
                },
            )
            .unwrap()
            .try_clone_std()
            .unwrap()
    };
    let first = open_lock();
    first.try_lock().unwrap();
    let second = open_lock();
    assert_eq!(
        io::Error::from(second.try_lock().unwrap_err()).kind(),
        io::ErrorKind::WouldBlock
    );
    drop(first);
    second.try_lock().unwrap();
}

#[test]
fn installed_runner_rejects_custom_and_relative_jobs() {
    let (temp, root, exe) = fixture();
    let custom = temp.path().join("custom");
    PrivateDir::ensure(&custom).unwrap();
    for jobs in [&custom, Path::new("jobs"), &root.join("jobs/../jobs")] {
        assert_eq!(
            runner_root(&exe, &root, jobs).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn uninstalled_runner_uses_disposable_jobs() {
    let (temp, root, _exe) = fixture();
    let other = temp.path().join("other-agent");
    fs::write(&other, b"other executable").unwrap();
    let jobs = temp.path().join("disposable");
    PrivateDir::ensure(&jobs).unwrap();
    assert_eq!(runner_root(&other, &root, &jobs).unwrap(), jobs);
}

#[cfg(unix)]
#[test]
fn installed_runner_rejects_symlinked_jobs_and_binary() {
    use std::os::unix::fs::symlink;
    let (temp, root, exe) = fixture();
    let alias = temp.path().join("jobs-alias");
    symlink(root.join("jobs"), &alias).unwrap();
    assert_eq!(
        runner_root(&exe, &root, &alias).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let actual = temp.path().join("actual-agent");
    fs::rename(&exe, &actual).unwrap();
    symlink(&actual, &exe).unwrap();
    assert_eq!(
        runner_root(&actual, &root, &root.join("jobs"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}
