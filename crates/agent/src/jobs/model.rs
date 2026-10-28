use super::*;

/// Caller-generated opaque identifier. It is never converted into an unchecked path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobId(ulid::Ulid);

impl JobId {
    /// Generate a new unpredictable identifier before the first submission.
    pub fn new() -> Self {
        Self(ulid::Ulid::generate())
    }

    /// Accept only canonical uppercase ULID text; reject path and alternate forms.
    pub fn parse(value: &str) -> io::Result<Self> {
        let id = value
            .parse::<ulid::Ulid>()
            .map_err(|_| invalid("job ID must be a canonical ULID"))?;
        if id.to_string() != value {
            return Err(invalid("job ID must use canonical uppercase ULID spelling"));
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
    pub(super) fn serialized(&self) -> io::Result<Vec<u8>> {
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

/// Operator projection of native Apalis status/result. Never stored in the payload.
/// Interrupted means uncertain,
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
}

/// Immutable authenticated request stored as the Apalis payload. No lifecycle fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobPayload {
    /// Canonical caller ULID, also the Apalis idempotency key.
    pub id: JobId,
    /// Fingerprint of the authenticated controller.
    pub controller_key_sha256: String,
    /// Digest of the exact serialized process specification.
    pub request_sha256: String,
    /// Source-pinned executable and exact argv/cwd.
    pub spec: JobSpec,
}

/// Read-only view of an immutable request and native Apalis status/result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobView {
    pub(crate) job: JobPayload,
    /// Native lifecycle/result projected for operators; never persisted here.
    pub state: JobState,
    pub(crate) started: bool,
}

impl std::ops::Deref for JobView {
    type Target = JobPayload;
    fn deref(&self) -> &Self::Target {
        &self.job
    }
}

impl TryFrom<String> for JobId {
    type Error = io::Error;
    fn try_from(value: String) -> io::Result<Self> {
        Self::parse(&value)
    }
}
impl From<JobId> for String {
    fn from(value: JobId) -> Self {
        value.to_string()
    }
}

impl JobPayload {
    pub(super) fn validate(&self, id: JobId) -> io::Result<()> {
        if self.id != id {
            return Err(invalid("durable job identity mismatch"));
        }
        validate_digest(&self.controller_key_sha256)?;
        if self.request_sha256 != format!("{:x}", Sha256::digest(self.spec.serialized()?)) {
            return Err(invalid("durable job digest mismatch"));
        }
        Ok(())
    }
}
