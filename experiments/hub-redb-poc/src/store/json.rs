use super::{HubStore, Snapshot, apply_host, apply_invite, apply_redeem};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

/// JSON-v2 baseline: full-state read/validate and private temp-file publication.
pub struct JsonStore {
    root: PathBuf,
    file: PathBuf,
    lock: PathBuf,
}

impl JsonStore {
    pub fn open(root: &Path) -> io::Result<Self> {
        if root.as_os_str().is_empty() {
            return Err(super::invalid("state root is required"));
        }
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        for parent in root.ancestors().filter(|path| !path.as_os_str().is_empty()) {
            if fs::symlink_metadata(parent)?.file_type().is_symlink() {
                return Err(super::invalid("state root traverses a symlink"));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::symlink_metadata(root)?.permissions().mode() & 0o077 != 0 {
                return Err(super::invalid("state root permissions are not private"));
            }
        }
        let root = fs::canonicalize(root)?;
        Ok(Self {
            file: root.join("registry-v2.json"),
            lock: root.join("registry-v2.lock"),
            root,
        })
    }

    fn with_write<T>(&self, update: impl FnOnce(&mut Snapshot) -> io::Result<T>) -> io::Result<T> {
        let lock = self.lock_exclusive()?;
        let mut state = match self.load() {
            Ok(state) => state,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Snapshot::empty(),
            Err(error) => return Err(error),
        };
        let result = update(&mut state)?;
        state.validate()?;
        let mut bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_JSON_BYTES {
            return Err(super::invalid("Hub state exceeds size limit"));
        }
        let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
        let publication = (|| {
            temp.write_all(&bytes)?;
            temp.as_file().sync_all()?;
            temp.persist(&self.file).map_err(|error| error.error)?;
            #[cfg(unix)]
            File::open(&self.root)?.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = publication {
            return match self.read_bounded() {
                Ok(current) if current == bytes => Err(io::Error::other(format!(
                    "commit outcome uncertain; readback matches: {error}"
                ))),
                Err(readback) if readback.kind() != io::ErrorKind::NotFound => {
                    Err(io::Error::other(format!(
                        "commit outcome uncertain; readback failed: {readback}"
                    )))
                }
                _ => Err(error),
            };
        }
        drop(lock);
        Ok(result)
    }
}

impl HubStore for JsonStore {
    fn snapshot(&self) -> io::Result<Snapshot> {
        let _lock = self.lock_shared()?;
        self.load()
    }
    fn register_host(&self, id: &str, name: &str, port: u16) -> io::Result<()> {
        self.with_write(|state| apply_host(state, id, name, port))
    }
    fn create_invite(&self, digest: &str, expires_at: i64) -> io::Result<()> {
        self.with_write(|state| apply_invite(state, digest, expires_at))
    }
    fn redeem_invite(&self, digest: &str, machine_id: &str, now: i64) -> io::Result<()> {
        self.with_write(|state| apply_redeem(state, digest, machine_id, now))
    }
}

impl JsonStore {
    fn lock_file(&self) -> io::Result<File> {
        if let Ok(metadata) = fs::symlink_metadata(&self.lock)
            && (!metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(super::invalid("state lock is not a regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.lock)
    }
    fn lock_exclusive(&self) -> io::Result<File> {
        self.lock_with(false)
    }
    fn lock_shared(&self) -> io::Result<File> {
        self.lock_with(true)
    }
    fn lock_with(&self, shared: bool) -> io::Result<File> {
        let lock = self.lock_file()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let attempt = if shared {
                lock.try_lock_shared()
            } else {
                lock.try_lock()
            };
            match attempt {
                Ok(()) => return Ok(lock),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Hub state writer lock timed out",
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
    }
    fn read_bounded(&self) -> io::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(&self.file)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() as usize > MAX_JSON_BYTES
        {
            return Err(super::invalid("unsafe or oversized Hub state file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(super::invalid("Hub state permissions are not private"));
            }
        }
        let mut bytes = Vec::new();
        File::open(&self.file)?
            .take(MAX_JSON_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_JSON_BYTES {
            return Err(super::invalid("Hub state exceeds size limit"));
        }
        Ok(bytes)
    }
    fn load(&self) -> io::Result<Snapshot> {
        match self.read_bounded() {
            Ok(bytes) => {
                let state: super::Snapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| super::invalid("Hub state is malformed"))?;
                state.validate()?;
                Ok(state)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Snapshot::empty()),
            Err(error) => Err(error),
        }
    }
}
