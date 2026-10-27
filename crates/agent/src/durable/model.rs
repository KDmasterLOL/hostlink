use super::*;

/// Caller-generated opaque identifier. It is never converted into an unchecked path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
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

    pub(super) fn can_transition_to(self, next: Self) -> bool {
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

impl JobRecord {
    pub(super) fn validate(&self, id: JobId) -> io::Result<()> {
        if self.version != SCHEMA_VERSION || self.id != id {
            return Err(invalid("durable job identity/version mismatch"));
        }
        validate_digest(&self.controller_key_sha256)?;
        if self.request_sha256 != format!("{:x}", Sha256::digest(self.spec.serialized()?)) {
            return Err(invalid("durable job digest mismatch"));
        }
        Ok(())
    }
}
