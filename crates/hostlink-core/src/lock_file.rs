//! Runtime-neutral bounded cross-process file locking.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

/// Acquires and returns a whole-file exclusive kernel lock within the supplied timeout.
///
/// The sidecar file is intentionally persistent. Ownership is the kernel lock attached to the
/// returned open file handle, so dropping/closing it or process death releases the lock. Callers
/// may store narrowly scoped persistent state in the file when their reconciliation contract
/// requires it.
pub fn acquire_exclusive_file_lock(
    path: impl AsRef<Path>,
    timeout: Duration,
    poll_interval: Duration,
) -> io::Result<File> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let started = Instant::now();

    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if started.elapsed() < timeout => {
                let remaining = timeout.saturating_sub(started.elapsed());
                let sleep_for = poll_interval.min(remaining);
                if sleep_for.is_zero() {
                    thread::yield_now();
                } else {
                    thread::sleep(sleep_for);
                }
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timed out waiting {:?} for exclusive lock {}",
                        timeout,
                        path.display()
                    ),
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_holder_child() {
        let Some(lock_path) = std::env::var_os("ONEC_CORE_LOCK_CHILD_PATH") else {
            return;
        };
        let ready = PathBuf::from(
            std::env::var_os("ONEC_CORE_LOCK_CHILD_READY").expect("child ready path"),
        );
        let _guard = acquire_exclusive_file_lock(
            PathBuf::from(lock_path),
            Duration::from_secs(2),
            Duration::from_millis(5),
        )
        .expect("child lock");
        fs::write(&ready, b"ready").expect("ready");
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn killed_process_releases_lock() {
        use std::process::Command;

        let root = tempfile::tempdir().expect("tempdir");
        let lock_path = root.path().join("store.lock");
        let ready = root.path().join("ready");
        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--exact")
            .arg("lock_file::tests::lock_holder_child")
            .arg("--nocapture")
            .env("ONEC_CORE_LOCK_CHILD_PATH", &lock_path)
            .env("ONEC_CORE_LOCK_CHILD_READY", &ready)
            .spawn()
            .expect("spawn lock child");

        for _ in 0..200 {
            if ready.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ready.exists(), "child never acquired lock");

        let error = acquire_exclusive_file_lock(
            &lock_path,
            Duration::from_millis(40),
            Duration::from_millis(5),
        )
        .expect_err("live child must own lock");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        child.kill().expect("kill lock child");
        let _ = child.wait().expect("wait lock child");

        acquire_exclusive_file_lock(&lock_path, Duration::from_secs(1), Duration::from_millis(5))
            .expect("kernel lock must be released after process death");
    }

    #[test]
    fn second_owner_times_out_and_drop_releases_lock() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("store.lock");
        let first = acquire_exclusive_file_lock(
            &path,
            Duration::from_millis(100),
            Duration::from_millis(5),
        )
        .expect("first lock");
        assert!(path.is_file(), "lock sidecar must exist while held");

        let started = Instant::now();
        let error =
            acquire_exclusive_file_lock(&path, Duration::from_millis(40), Duration::from_millis(5))
                .expect_err("second lock must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(35));

        drop(first);
        acquire_exclusive_file_lock(&path, Duration::from_millis(100), Duration::from_millis(5))
            .expect("lock after release");
    }
}
