use serde::{Deserialize, Serialize};

/// Job identifier must be a canonical uppercase ULID.
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

/// One idempotent admission request. Submitting the same ID does not enqueue
/// an extra job; native Apalis crash recovery may independently retry it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// Canonical uppercase ULID chosen by the caller.
    pub id: JobId,
    /// Exact executable and argv manifest.
    pub spec: JobSpec,
}

/// Status query for a previously admitted job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Status {
    /// Canonical uppercase ULID returned by the original start request.
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
    /// Canonical uppercase ULID returned by the original start request.
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

/// Read-only projection of native Agent queue status/result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobState {
    /// Accepted but not yet running.
    #[serde(deserialize_with = "deserialize_empty_state")]
    Prepared,
    /// Worker is running.
    #[serde(deserialize_with = "deserialize_empty_state")]
    Running,
    /// Worker exited; `code` preserves its actual exit code.
    Exited {
        /// Actual process exit code, including nonzero exits.
        code: i32,
    },
    /// Agent recorded a worker failure.
    #[serde(deserialize_with = "deserialize_empty_state")]
    Failed,
    /// Native worker cancellation with an uncertain execution outcome.
    #[serde(deserialize_with = "deserialize_empty_state")]
    Interrupted,
}

// Serde's internally tagged unit visitor ignores fields even with
// deny_unknown_fields. Reject all remaining fields after serde consumes the tag.
fn deserialize_empty_state<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<(), D::Error> {
    let fields =
        std::collections::BTreeMap::<String, serde::de::IgnoredAny>::deserialize(deserializer)?;
    match fields.keys().next() {
        Some(field) => Err(serde::de::Error::unknown_field(field, &[])),
        None => Ok(()),
    }
}

/// Exact status returned by the Agent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStatus {
    /// Canonical uppercase job ULID.
    pub id: JobId,
    /// Current persisted lifecycle state.
    pub state: JobState,
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
