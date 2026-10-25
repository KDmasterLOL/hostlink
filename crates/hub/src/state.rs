use crate::{MachineId, RegisteredHost};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
const STATE_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const STATE_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(10);

pub(crate) const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_INVITES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub version: u32,
    #[serde(default)]
    pub hosts: BTreeMap<MachineId, RegisteredHost>,
    #[serde(default)]
    pub invites: BTreeMap<String, InviteRecord>,
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 2,
            hosts: BTreeMap::new(),
            invites: BTreeMap::new(),
            audit: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InviteRecord {
    pub digest: String,
    pub expires_at: i64,
    pub used: bool,
    pub name: Option<String>,
    pub rotate_machine_id: Option<MachineId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEntry {
    pub at: i64,
    pub action: String,
    pub machine_id: Option<MachineId>,
}

pub(crate) struct StateStore {
    root: PathBuf,
    state_path: PathBuf,
    lock_path: PathBuf,
}

pub(crate) struct LockedState {
    store: StateStore,
    _lock: File,
    pub state: State,
}

impl StateStore {
    pub fn open(root: &Path) -> io::Result<Self> {
        validate_or_create_private_root(root)?;
        let root = fs::canonicalize(root)?;
        Ok(Self {
            state_path: root.join("registry-v2.json"),
            lock_path: root.join("registry-v2.lock"),
            root,
        })
    }

    pub fn lock(&self) -> io::Result<LockedState> {
        if let Ok(meta) = fs::symlink_metadata(&self.lock_path)
            && (!meta.is_file() || meta.file_type().is_symlink())
        {
            return Err(invalid("state lock must be a regular file"));
        }
        #[cfg(unix)]
        if let Ok(meta) = fs::symlink_metadata(&self.lock_path) {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(invalid("state lock permissions must be private"));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&self.lock_path)?;
        let deadline = std::time::Instant::now() + STATE_LOCK_TIMEOUT;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(STATE_LOCK_POLL)
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
        let state = self.load()?;
        Ok(LockedState {
            store: self.clone(),
            _lock: lock,
            state,
        })
    }

    fn load(&self) -> io::Result<State> {
        match fs::symlink_metadata(&self.state_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(State::default()),
            Err(error) => Err(error),
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() as usize > MAX_STATE_BYTES =>
            {
                Err(invalid("Hub state must be a bounded regular file"))
            }
            #[cfg(unix)]
            Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
                Err(invalid("Hub state permissions must be private"))
            }
            Ok(_) => {
                let file = File::open(&self.state_path)?;
                let mut bytes = Vec::new();
                file.take(MAX_STATE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_STATE_BYTES {
                    return Err(invalid("Hub state exceeds size limit"));
                }
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("Hub state is malformed"))?;
                if state.version != 2 {
                    return Err(invalid("unsupported Hub state version"));
                }
                validate_state(&state)?;
                Ok(state)
            }
        }
    }
}
impl Clone for StateStore {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            state_path: self.state_path.clone(),
            lock_path: self.lock_path.clone(),
        }
    }
}

impl LockedState {
    pub fn commit(mut self) -> Result<(), CommitError> {
        if self.state.invites.len() > MAX_INVITES {
            return Err(CommitError::NotCommitted(invalid(
                "invite count exceeds limit",
            )));
        }
        if self.state.audit.len() > 10_000 {
            let remove = self.state.audit.len() - 10_000;
            self.state.audit.drain(..remove);
        }
        let mut bytes = serde_json::to_vec(&self.state)
            .map_err(|_| CommitError::NotCommitted(invalid("state serialization failed")))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_STATE_BYTES {
            return Err(CommitError::NotCommitted(invalid(
                "Hub state exceeds size limit",
            )));
        }
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| {
            CommitError::NotCommitted(io::Error::other("secure random source unavailable"))
        })?;
        let temp = self
            .store
            .root
            .join(format!(".registry-v2-{}.tmp", hex::encode(nonce)));
        let mut file = private_new_file(&temp).map_err(CommitError::NotCommitted)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp, &self.store.state_path)?;
            #[cfg(unix)]
            File::open(&self.store.root)?.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return match read_bounded(&self.store.state_path) {
                Ok(current) if current == bytes => Err(CommitError::Uncertain(error)),
                Err(readback) if readback.kind() != io::ErrorKind::NotFound => {
                    Err(CommitError::Uncertain(io::Error::other(format!(
                        "publication failed; readback failed: {readback}"
                    ))))
                }
                _ => Err(CommitError::NotCommitted(error)),
            };
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum CommitError {
    NotCommitted(io::Error),
    Uncertain(io::Error),
}
impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(e) => write!(f, "not committed: {e}"),
            Self::Uncertain(e) => {
                write!(f, "commit outcome uncertain; reconcile before retry: {e}")
            }
        }
    }
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() as usize > MAX_STATE_BYTES {
        return Err(invalid("unsafe state readback"));
    }
    let mut v = Vec::new();
    File::open(path)?
        .take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut v)?;
    if v.len() > MAX_STATE_BYTES {
        return Err(invalid("state readback exceeds limit"));
    }
    Ok(v)
}
fn private_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    Ok(file)
}

fn validate_or_create_private_root(root: &Path) -> io::Result<()> {
    if root.as_os_str().is_empty() {
        return Err(invalid("state root is required"));
    }
    for component in root.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(metadata) = fs::symlink_metadata(component)
            && metadata.file_type().is_symlink()
        {
            return Err(invalid("state root path must not traverse symlinks"));
        }
    }
    if !root.exists() {
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "state root must be a real directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("state root permissions must be private (0700)"));
        }
    }
    for component in root.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        if fs::symlink_metadata(component)?.file_type().is_symlink() {
            return Err(invalid("state root path must not traverse symlinks"));
        }
    }
    Ok(())
}

fn validate_state(state: &State) -> io::Result<()> {
    if state.hosts.len() > 100_000
        || state.invites.len() > MAX_INVITES
        || state.audit.len() > 10_000
    {
        return Err(invalid("Hub state exceeds record limits"));
    }
    let mut names = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (id, host) in &state.hosts {
        if crate::server::validate_name(&host.name).is_err()
            || host
                .display_name
                .as_deref()
                .is_some_and(|n| n.is_empty() || n.len() > 128 || n.chars().any(char::is_control))
            || id != &host.machine_id
            || host.remote_port == 0
            || !names.insert(host.name.to_lowercase())
            || !ports.insert(host.remote_port)
        {
            return Err(invalid(
                "Hub state contains duplicate or inconsistent host identity",
            ));
        }
        for value in [&host.ssh_public_key, &host.ssh_host_public_key] {
            let canonical = crate::canonical_ed25519_public_key(value)
                .map_err(|_| invalid("Hub state contains an invalid SSH key"))?;
            if !keys.insert(canonical) {
                return Err(invalid("Hub state contains a reused SSH key"));
            }
        }
    }
    for (key, invite) in &state.invites {
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || key != &invite.digest
            || invite
                .name
                .as_deref()
                .is_some_and(|n| crate::server::validate_name(n).is_err())
        {
            return Err(invalid("Hub state contains an invalid invite digest"));
        }
    }
    Ok(())
}
pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

pub(crate) fn allocate_port(
    state: &State,
    from: u16,
    to: u16,
    reserved: &BTreeSet<u16>,
    machine_id: &MachineId,
) -> Option<u16> {
    if from == 0 || from > to {
        return None;
    }
    let used: BTreeSet<u16> = state.hosts.values().map(|h| h.remote_port).collect();
    let count = usize::from(to - from) + 1;
    let hash = sha2::Sha256::digest(machine_id.as_str().as_bytes());
    let start = (u16::from_be_bytes([hash[0], hash[1]]) as usize) % count;
    (0..count)
        .map(|offset| from + ((start + offset) % count) as u16)
        .find(|p| !used.contains(p) && !reserved.contains(p))
}
use sha2::Digest;
