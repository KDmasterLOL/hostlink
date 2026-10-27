//! Source-pinned durable job identities, private state and update admission guards.
//!
//! Durable Agent-owned job records, process output and lifecycle state.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_JOBS: usize = 4096;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_ARTIFACTS_PER_CONTROLLER: usize = 128;
pub(crate) const MAX_JOB_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_OUTPUT_CHUNK_BYTES: usize = 24 * 1024;

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

/// Private per-controller upload and sealed-artifact roots, both outside jobs_root.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactStore {
    owner_root: PathBuf,
}

impl ArtifactStore {
    pub(crate) fn open(jobs_root: &Path, owner: &str) -> io::Result<Self> {
        validate_digest(owner)?;
        let install_root = jobs_root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        validate_private_path(install_root, true)?;
        let artifacts_root = install_root.join("artifacts");
        create_private_directory(&artifacts_root)?;
        let owner_root = artifacts_root.join(owner);
        create_private_directory(&owner_root)?;
        create_private_directory(&owner_root.join("uploads"))?;
        create_private_directory(&owner_root.join("sealed"))?;
        Ok(Self { owner_root })
    }

    pub(crate) fn upload_root(&self) -> PathBuf {
        self.owner_root.join("uploads")
    }

    pub(crate) fn sealed_root(&self) -> PathBuf {
        self.owner_root.join("sealed")
    }

    pub(crate) fn seal(
        &self,
        name: &str,
        expected_sha256: &str,
        expected_size: u64,
    ) -> io::Result<PathBuf> {
        validate_digest(expected_sha256)?;
        if expected_size > MAX_ARTIFACT_BYTES || name != format!("{expected_sha256}.upload") {
            return Err(invalid("artifact name, digest, or size is invalid"));
        }
        let _lock = exclusive_lock(&self.owner_root.join("seal.lock"))?;
        validate_private_path(
            self.owner_root
                .parent()
                .ok_or_else(|| invalid("controller artifact root has no parent"))?,
            true,
        )?;
        validate_private_path(
            self.owner_root
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| invalid("artifact root has no install parent"))?,
            true,
        )?;
        validate_private_path(&self.owner_root, true)?;
        let uploads = self.owner_root.join("uploads");
        let sealed = self.owner_root.join("sealed");
        validate_private_path(&uploads, true)?;
        validate_private_path(&sealed, true)?;
        let source = uploads.join(name);
        validate_private_path(&source, false)?;
        let target = sealed.join(format!("{expected_sha256}.program"));

        match fs::symlink_metadata(&target) {
            Ok(_) => {
                validate_private_path(&target, false)?;
                verify_artifact(&target, expected_sha256, expected_size)?;
                return target.canonicalize();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut input_options = OpenOptions::new();
        input_options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            input_options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut input = input_options.open(&source)?;
        let input_meta = input.metadata()?;
        if !input_meta.is_file() || input_meta.len() != expected_size {
            return Err(invalid(
                "uploaded artifact length does not match seal request",
            ));
        }
        if input_meta.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("uploaded artifact exceeds configured limit"));
        }
        let mut output_options = OpenOptions::new();
        output_options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            output_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut output = output_options.open(&target)?;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = input.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(read as u64)
                    .ok_or_else(|| invalid("artifact size overflow"))?;
                if total > expected_size || total > MAX_ARTIFACT_BYTES {
                    return Err(invalid("uploaded artifact changed during seal"));
                }
                hasher.update(&buffer[..read]);
                output.write_all(&buffer[..read])?;
            }
            let digest = format!("{:x}", hasher.finalize());
            if total != expected_size || digest != expected_sha256 {
                return Err(invalid(
                    "uploaded artifact digest or length does not match seal request",
                ));
            }
            output.sync_all()?;
            restrict_sealed_artifact(&target, &output)?;
            sync_directory(&sealed)?;
            Ok(())
        })();
        if let Err(error) = result {
            drop(output);
            let _ = fs::remove_file(&target);
            return Err(error);
        }
        target.canonicalize()
    }
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => restrict_private_path(path, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            validate_private_path(path, true)
        }
        Err(error) => Err(error),
    }
}

fn verify_artifact(path: &Path, expected_sha256: &str, expected_size: u64) -> io::Result<()> {
    validate_private_path(path, false)?;
    let mut file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o222 != 0 || mode & 0o111 == 0 {
            return Err(invalid(
                "sealed artifact permissions are not executable and read-only",
            ));
        }
    }
    if file.metadata()?.len() != expected_size || expected_size > MAX_ARTIFACT_BYTES {
        return Err(invalid("sealed artifact length conflicts with repeat seal"));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(invalid("sealed artifact conflicts with repeat seal"));
    }
    Ok(())
}

fn restrict_sealed_artifact(path: &Path, file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !named.is_file() || opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid("sealed artifact path changed during publication"));
        }
        file.set_permissions(fs::Permissions::from_mode(0o500))?;
    }
    #[cfg(windows)]
    {
        let _ = file;
        set_private_windows_acl(path, false)?;
    }
    validate_private_path(path, false)
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

    pub(crate) fn artifacts(&self, owner: &str) -> io::Result<ArtifactStore> {
        ArtifactStore::open(&self.root, owner)
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
        let missing = match fs::symlink_metadata(&dir) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        if missing {
            let mut count = 0_usize;
            for entry in fs::read_dir(&self.root)? {
                let _ = entry?;
                count = count.saturating_add(1);
                if count >= MAX_JOBS {
                    return Err(invalid("maximum number of durable jobs reached"));
                }
            }
        }
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

    /// Recover nonterminal records left by a previous Agent process without replaying them.
    pub fn recover_nonterminal(&self) -> io::Result<()> {
        let install_root = self
            .root
            .parent()
            .ok_or_else(|| invalid("jobs root has no parent"))?;
        let _update_lock = acquire_update_lock(install_root)?;
        for child in fs::read_dir(&self.root)? {
            let child = child?;
            let id_name = child.file_name();
            let id = id_name
                .to_str()
                .ok_or_else(|| invalid("job directory name is not UTF-8"))
                .and_then(JobId::parse)?;
            let record = self.read(id)?;
            if matches!(record.state, JobState::Prepared | JobState::Running) {
                self.transition(
                    id,
                    &record.controller_key_sha256,
                    record.state,
                    JobState::Interrupted,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn output_path(&self, id: JobId, stream: JobOutput) -> PathBuf {
        self.job_dir(id).join(stream.file_name())
    }

    /// Read a bounded raw output slice, preserving arbitrary bytes across reconnects.
    pub(crate) fn read_output(
        &self,
        id: JobId,
        owner: &str,
        stream: JobOutput,
        offset: u64,
    ) -> io::Result<(Vec<u8>, u64, bool)> {
        let record = self.lookup(id, owner)?;
        let path = self.output_path(id, stream);
        let mut file = match read_bounded_output(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if offset != 0 {
                    return Err(invalid("output offset exceeds available bytes"));
                }
                if record.state.blocks_update() {
                    return Ok((Vec::new(), 0, false));
                }
                return Ok((Vec::new(), 0, true));
            }
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        if offset > len {
            return Err(invalid("output offset exceeds available bytes"));
        }
        use std::io::Seek;
        file.seek(io::SeekFrom::Start(offset))?;
        let mut bytes = vec![0; MAX_OUTPUT_CHUNK_BYTES.min((len - offset) as usize)];
        file.read_exact(&mut bytes)?;
        let next = offset + bytes.len() as u64;
        Ok((bytes, next, !record.state.blocks_update() && next == len))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JobOutput {
    Stdout,
    Stderr,
}

impl JobOutput {
    fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.bin",
            Self::Stderr => "stderr.bin",
        }
    }
}

pub(crate) fn open_output_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    restrict_private_path(path, false)?;
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
}

fn read_bounded_output(path: &Path) -> io::Result<File> {
    validate_private_path(path, false)?;
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_JOB_OUTPUT_BYTES {
        return Err(invalid("job output exceeds configured limit"));
    }
    Ok(file)
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

pub(crate) fn validate_private_path(path: &Path, directory: bool) -> io::Result<()> {
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

pub(crate) fn restrict_private_path(path: &Path, directory: bool) -> io::Result<()> {
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
mod tests;
