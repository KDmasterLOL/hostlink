//! Source-pinned durable job identities, private state and update admission guards.
//!
//! This module deliberately does not start a process or claim reconnect parity yet.
//! A transport-independent worker can later consume admitted jobs, but it must never
//! infer permission to start again from a lost SSH acknowledgement.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_JOBS: usize = 4096;

/// A shared file lock: job admission and Agent update must exclude one another.
pub const UPDATE_LOCK_FILE: &str = "update.lock";

/// Caller-generated opaque identifier. It is never converted into an unchecked path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(Uuid);

impl JobId {
    /// Generate a new unpredictable identifier before the first submission.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Accept only canonical lowercase UUID text; reject path and alternate forms.
    pub fn parse(value: &str) -> io::Result<Self> {
        let id = Uuid::parse_str(value).map_err(|_| invalid("job ID must be a canonical UUID"))?;
        if id.to_string() != value {
            return Err(invalid("job ID must use canonical lowercase UUID spelling"));
        }
        Ok(Self(id))
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The precise process request and source artifact selected by the caller.
/// Secrets should be supplied by a future dedicated private handoff, not argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub source_sha256: String,
}

impl JobSpec {
    fn serialized(&self) -> io::Result<Vec<u8>> {
        if self.program.trim().is_empty()
            || self.program.contains('\0')
            || self.args.iter().any(|arg| arg.contains('\0'))
            || self
                .cwd
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(invalid("job command/argv/cwd is empty or contains NUL"));
        }
        validate_digest(&self.source_sha256)?;
        let data = serde_json::to_vec(self).map_err(io::Error::other)?;
        if data.len() > MAX_RECORD_BYTES {
            return Err(invalid("job manifest exceeds configured size"));
        }
        Ok(data)
    }
}

/// The persisted state of a single admitted job. Interrupted means uncertain,
/// not permission to rerun an operation or replace the Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum JobState {
    Prepared,
    Running,
    Exited { code: i32 },
    Failed,
    Interrupted,
}

impl JobState {
    /// Prepared/Running/Interrupted jobs must prevent Agent replacement.
    pub fn blocks_update(self) -> bool {
        matches!(self, Self::Prepared | Self::Running | Self::Interrupted)
    }

    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Prepared,
                Self::Running | Self::Failed | Self::Interrupted
            ) | (
                Self::Running,
                Self::Exited { .. } | Self::Failed | Self::Interrupted
            )
        )
    }
}

/// A persisted authenticated identity, exact command digest and lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub version: u32,
    pub id: JobId,
    pub controller_key_sha256: String,
    pub request_sha256: String,
    pub spec: JobSpec,
    pub state: JobState,
}

/// Admission is idempotent: an already accepted ID never launches another worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Created(JobRecord),
    Existing(JobRecord),
}

/// One existing user-owned private directory for source-exact Agent job records.
#[derive(Debug, Clone)]
pub struct JobStore {
    root: PathBuf,
}

impl JobStore {
    /// Open only a pre-provisioned private root; never make an unsafe public root.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        validate_private_path(&root, true)?;
        let parent = root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        validate_private_path(parent, true)?;
        Ok(Self { root })
    }

    /// Commit a new request before acknowledging it. Existing matching IDs never rerun.
    pub fn admit(
        &self,
        id: JobId,
        controller_key_sha256: &str,
        spec: &JobSpec,
    ) -> io::Result<Admission> {
        validate_digest(controller_key_sha256)?;
        let bytes = spec.serialized()?;
        let request_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let _update_lock = acquire_update_lock(
            self.root
                .parent()
                .ok_or_else(|| invalid("jobs root has no parent"))?,
        )?;
        let dir = self.job_dir(id);
        match fs::create_dir(&dir) {
            Ok(()) => {
                restrict_private_path(&dir, true)?;
                let record = JobRecord {
                    version: SCHEMA_VERSION,
                    id,
                    controller_key_sha256: controller_key_sha256.to_owned(),
                    request_sha256,
                    spec: spec.clone(),
                    state: JobState::Prepared,
                };
                write_new_private(&dir.join("record.json"), &record)?;
                // A torn initial record must remain unusable until explicitly reconciled.
                Ok(Admission::Created(record))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let stored = self.lookup(id, controller_key_sha256)?;
                if stored.request_sha256 != request_sha256 || stored.spec != *spec {
                    return Err(invalid("job ID already belongs to a different request"));
                }
                Ok(Admission::Existing(stored))
            }
            Err(error) => Err(error),
        }
    }

    /// Look up a record only for the authenticated controller key that created it.
    pub fn lookup(&self, id: JobId, controller_key_sha256: &str) -> io::Result<JobRecord> {
        validate_digest(controller_key_sha256)?;
        let record = self.read(id)?;
        if record.controller_key_sha256 != controller_key_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job is owned by a different authenticated key",
            ));
        }
        Ok(record)
    }

    /// Persist an explicit state transition; no automatic retry of Interrupted work.
    pub fn transition(
        &self,
        id: JobId,
        controller_key_sha256: &str,
        expected: JobState,
        next: JobState,
    ) -> io::Result<JobRecord> {
        let dir = self.job_dir(id);
        validate_private_path(&dir, true)?;
        let _state_lock = exclusive_lock(&dir.join("state.lock"))?;
        let mut record = self.lookup(id, controller_key_sha256)?;
        if record.state != expected || !record.state.can_transition_to(next) {
            return Err(invalid("invalid or stale job state transition"));
        }
        record.state = next;
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        atomic_replace_private(&dir.join("record.json"), &bytes)?;
        Ok(record)
    }

    fn job_dir(&self, id: JobId) -> PathBuf {
        self.root.join(id.to_string())
    }

    fn read(&self, id: JobId) -> io::Result<JobRecord> {
        let dir = self.job_dir(id);
        validate_private_path(&dir, true)?;
        let bytes = read_bounded_private(&dir.join("record.json"))?;
        let record: JobRecord = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("job record is invalid or incomplete"))?;
        if record.version != SCHEMA_VERSION || record.id != id {
            return Err(invalid("job record identity/version mismatch"));
        }
        validate_digest(&record.controller_key_sha256)?;
        if record.request_sha256 != format!("{:x}", Sha256::digest(record.spec.serialized()?)) {
            return Err(invalid("job record digest mismatch"));
        }
        Ok(record)
    }
}

/// Conservative updater interlock. Invalid/unknown entries fail CLOSED.
pub fn active_ids(jobs_root: &Path) -> io::Result<Vec<String>> {
    let store = JobStore::open(jobs_root)?;
    let mut active = Vec::new();
    let mut scanned = 0_usize;
    for child in fs::read_dir(&store.root)? {
        let child = child?;
        scanned += 1;
        if scanned > MAX_JOBS {
            return Err(invalid("too many job entries to prove update safety"));
        }
        let id_name = child.file_name();
        let id = id_name
            .to_str()
            .ok_or_else(|| invalid("job directory name is not UTF-8"))
            .and_then(JobId::parse)?;
        let record = store.read(id)?;
        if record.state.blocks_update() {
            active.push(id.to_string());
        }
    }
    active.sort();
    Ok(active)
}

fn validate_digest(value: &str) -> io::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "SHA-256 digest must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_private_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
        return Err(invalid(
            "private path is a symlink or has the wrong file type",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owner/private permissions",
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_acl(path, &metadata)?;
    Ok(())
}

fn restrict_private_path(path: &Path, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    set_private_windows_acl(path, directory)?;
    validate_private_path(path, directory)
}

fn write_new_private(path: &Path, value: &JobRecord) -> io::Result<()> {
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    if data.len() > MAX_RECORD_BYTES {
        return Err(invalid("serialized job record exceeds size limit"));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    restrict_private_path(path, false)?;
    file.write_all(&data)?;
    file.sync_all()?;
    sync_directory(path.parent().expect("created job file has a parent"))
}

fn read_bounded_private(path: &Path) -> io::Result<Vec<u8>> {
    validate_private_path(path, false)?;
    let mut input = File::open(path)?.take(MAX_RECORD_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("job state exceeded its maximum size"));
    }
    Ok(bytes)
}

fn atomic_replace_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_RECORD_BYTES {
        return Err(invalid("job record exceeds maximum size"));
    }
    validate_private_path(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("record has no parent"))?;
    let mut stage = tempfile::NamedTempFile::new_in(parent)?;
    restrict_private_path(stage.path(), false)?;
    stage.write_all(data)?;
    stage.as_file().sync_all()?;
    stage.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

/// A single admission/update lock shared by JobStore and the separate updater.
pub fn acquire_update_lock(install_root: &Path) -> io::Result<File> {
    validate_private_path(install_root, true)?;
    exclusive_lock(&install_root.join(UPDATE_LOCK_FILE))
}

fn exclusive_lock(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(invalid("lock file is not a regular file"));
    }
    let file = opts.open(path)?;
    restrict_private_path(path, false)?;
    file.lock()?;
    Ok(file)
}

fn sync_directory(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

#[cfg(windows)]
fn validate_windows_acl(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
    };
    use windows_permissions::{LocalBox, Sid};
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows private path is a reparse point"));
    }
    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let sddl =
        ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, SecurityInformation::Dacl)
            .map_err(io::Error::other)?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows ACL inherits permissions",
        ));
    }
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows private path owner does not match current Agent user",
        ));
    }
    let system: LocalBox<Sid> = "S-1-5-18".parse().map_err(io::Error::other)?;
    let admins: LocalBox<Sid> = "S-1-5-32-544".parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("private path missing Windows DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("unreadable Windows DACL entry"))?;
        if !matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        let sid = ace
            .sid()
            .ok_or_else(|| invalid("unverifiable Windows ACE"))?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != admins.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "foreign Windows ACL allow entry",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_private_windows_acl(path: &Path, directory: bool) -> io::Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let current = ConvertSidToStringSid(&current).map_err(io::Error::other)?;
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{flags};FA;;;{})", current.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("cannot create private Windows DACL"))?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, JobStore) {
        let root = tempfile::tempdir().expect("private fixture parent");
        restrict_private_path(root.path(), true).unwrap();
        let jobs = root.path().join("jobs");
        fs::create_dir(&jobs).unwrap();
        restrict_private_path(&jobs, true).unwrap();
        let store = JobStore::open(jobs).unwrap();
        (root, store)
    }

    fn sample() -> JobSpec {
        JobSpec {
            program: "echo".into(),
            args: vec!["hello".into()],
            cwd: None,
            source_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn same_identity_is_idempotent_and_conflict_fails() {
        let (_temp, store) = fixture();
        let id = JobId::new();
        let owner = "b".repeat(64);
        assert!(matches!(
            store.admit(id, &owner, &sample()).unwrap(),
            Admission::Created(_)
        ));
        assert!(matches!(
            store.admit(id, &owner, &sample()).unwrap(),
            Admission::Existing(_)
        ));
        let mut conflict = sample();
        conflict.args.push("again".into());
        assert!(store.admit(id, &owner, &conflict).is_err());
        assert!(store.lookup(id, &"c".repeat(64)).is_err());
        assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
    }

    #[test]
    fn terminal_jobs_no_longer_block_but_interrupted_jobs_do() {
        let (_temp, store) = fixture();
        let id = JobId::new();
        let owner = "b".repeat(64);
        store.admit(id, &owner, &sample()).unwrap();
        store
            .transition(id, &owner, JobState::Prepared, JobState::Running)
            .unwrap();
        assert_eq!(active_ids(&store.root).unwrap(), vec![id.to_string()]);
        store
            .transition(id, &owner, JobState::Running, JobState::Exited { code: 7 })
            .unwrap();
        assert!(active_ids(&store.root).unwrap().is_empty());
        assert!(
            store
                .transition(id, &owner, JobState::Exited { code: 7 }, JobState::Running)
                .is_err()
        );

        let next_id = JobId::new();
        store.admit(next_id, &owner, &sample()).unwrap();
        store
            .transition(next_id, &owner, JobState::Prepared, JobState::Interrupted)
            .unwrap();
        assert_eq!(active_ids(&store.root).unwrap(), vec![next_id.to_string()]);
    }

    #[test]
    fn private_root_and_corrupt_record_fail_closed() {
        let (temp, store) = fixture();
        let id = JobId::new();
        let owner = "b".repeat(64);
        store.admit(id, &owner, &sample()).unwrap();
        fs::write(store.job_dir(id).join("record.json"), b"broken").unwrap();
        assert!(active_ids(&store.root).is_err());
        assert!(JobId::parse("../root").is_err());
        assert!(JobId::parse(&id.to_string().to_uppercase()).is_err());
        let bad_root = temp.path().join("public");
        fs::create_dir(&bad_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bad_root, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(JobStore::open(&bad_root).is_err());
        }
    }

    #[test]
    fn torn_admission_prevents_update_and_no_retry_is_inferred() {
        let (_temp, store) = fixture();
        let id = JobId::new();
        let orphan = store.job_dir(id);
        fs::create_dir(&orphan).unwrap();
        restrict_private_path(&orphan, true).unwrap();
        // A crash after reserving an ID but before committing the record is UNKNOWN.
        assert!(active_ids(&store.root).is_err());
        assert!(store.admit(id, &"b".repeat(64), &sample()).is_err());
        assert!(!orphan.join("record.json").exists());
    }

    #[test]
    fn concurrent_admission_never_creates_two_records() {
        let (_temp, store) = fixture();
        let shared = std::sync::Arc::new(store);
        let id = JobId::new();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = shared.clone();
            handles.push(std::thread::spawn(move || {
                store.admit(id, &"b".repeat(64), &sample())
            }));
        }
        let mut created = 0;
        for handle in handles {
            if let Ok(Admission::Created(_)) = handle.join().unwrap() {
                created += 1;
            }
        }
        assert_eq!(
            created, 1,
            "atomic UUID reservation must have exactly one winner"
        );
        let authenticated = shared.lookup(id, &"b".repeat(64)).unwrap();
        assert_eq!(authenticated.state, JobState::Prepared);
        assert_eq!(active_ids(&shared.root).unwrap(), vec![id.to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_job_directory_is_never_resolved() {
        use std::os::unix::fs::symlink;
        let (_temp, store) = fixture();
        let id = JobId::new();
        symlink(".", store.job_dir(id)).unwrap();
        assert!(active_ids(&store.root).is_err());
    }
}
