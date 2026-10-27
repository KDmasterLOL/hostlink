use serde::{Deserialize, Serialize};

/// Job identifier must be a canonical lowercase UUID.
pub type JobId = String;

/// Executable and exact argument vector admitted for a durable job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Absolute executable path.
    pub program: String,
    /// Arguments passed without shell interpretation.
    pub args: Vec<String>,
    /// Optional working directory.
    pub cwd: Option<String>,
    /// Lowercase SHA-256 digest of the executable.
    pub source_sha256: String,
}

/// One idempotent admission request. Reusing this ID never implies a retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// Canonical lowercase UUID chosen by the caller.
    pub id: JobId,
    /// Exact executable and argv manifest.
    pub spec: JobSpec,
}

/// Status query for a previously admitted job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Status {
    /// Canonical lowercase UUID returned by the original start request.
    pub id: JobId,
}

/// Requests cancellation by canonical durable job identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Cancel {
    pub id: JobId,
}

/// Selects one persisted output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Reads bytes starting at a persisted byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    /// Canonical lowercase UUID returned by the original start request.
    pub id: JobId,
    /// Output stream to read.
    pub stream: JobStream,
    /// Exact byte offset from which to continue.
    pub offset: u64,
}

/// Requests Agent-side verification and sealing of the exclusively uploaded artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seal {
    /// Digest-bound SFTP staging name: `<sha256>.upload`.
    pub name: String,
    /// Expected lowercase SHA-256 digest.
    pub sha256: String,
    /// Exact uploaded byte length.
    pub size: u64,
}

/// Agent-resolved executable path and verified artifact digest.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedArtifact {
    /// Canonical absolute path selected by the Agent.
    pub program: String,
    /// Digest verified by the Agent.
    pub sha256: String,
}

/// Persisted Agent job lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStateKind {
    /// Accepted but not yet running.
    Prepared,
    /// Worker is running.
    Running,
    /// Worker exited; `code` preserves its actual exit code.
    Exited,
    /// Agent recorded a worker failure.
    Failed,
    /// Agent restarted or otherwise lost the worker before terminal state.
    Interrupted,
}

/// Exact status returned by the Agent.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStatus {
    /// Canonical lowercase job UUID.
    pub id: JobId,
    /// Current persisted lifecycle state.
    pub state: JobState,
}

/// Lifecycle data, retaining a nonzero process exit code.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobState {
    /// Exact state name.
    pub state: JobStateKind,
    /// Process exit code when known.
    #[serde(default)]
    pub code: Option<i32>,
}

/// One decoded raw output chunk and its continuation point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobOutput {
    /// Job lifecycle state observed with this read.
    pub status: JobStatus,
    /// Raw, possibly non-UTF-8 bytes.
    pub data: Vec<u8>,
    /// Offset to use for the next request.
    pub next_offset: u64,
    /// Whether this stream has reached EOF.
    pub eof: bool,
}
