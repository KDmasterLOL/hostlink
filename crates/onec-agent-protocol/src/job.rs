//! Persistent agent job state and durable job metadata.

use crate::{ResultSetInfo, digest::is_lowercase_sha256, validate_result_set_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Closed effect label attached to one Agent-observed native invocation.
///
/// The label is caller-declared. The Agent signs it with the invocation identity but does not
/// inspect test behavior or prove that the executable stayed within that effect.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeExecutionEffect {
    /// Caller declares that the invocation is read-only.
    ReadOnly,
    /// Caller declares that the invocation mutates only run-owned state.
    RunOwned,
    /// Caller declares that the invocation uses a disposable target.
    Disposable,
}

/// Typed mapping for one input file staged inside a durable run-local workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "RunLocalMappedFileWire")]
pub struct RunLocalMappedFile {
    /// Child environment variable receiving the file path.
    pub(crate) environment_name: String,
    /// SHA-256 of the exact staged bytes.
    pub(crate) sha256: String,
}

#[derive(Deserialize)]
pub(crate) struct RunLocalMappedFileWire {
    environment_name: String,
    sha256: String,
}

impl TryFrom<RunLocalMappedFileWire> for RunLocalMappedFile {
    type Error = String;

    fn try_from(value: RunLocalMappedFileWire) -> Result<Self, Self::Error> {
        Self::try_new(value.environment_name, value.sha256)
    }
}

impl RunLocalMappedFile {
    /// Creates a validated mapped-file identity.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn try_new(environment_name: String, sha256: String) -> Result<Self, String> {
        let value = Self {
            environment_name,
            sha256,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the environment-variable name and lowercase SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        if self.environment_name.is_empty()
            || !self
                .environment_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("mapped run-local environment name is invalid".to_owned());
        }
        validate_lowercase_sha256("mapped run-local file", &self.sha256)
    }

    /// Returns the mapped environment-variable name.
    pub fn environment_name(&self) -> &str {
        &self.environment_name
    }

    /// Returns the lowercase SHA-256 digest of the staged bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Durable binding between a local candidate and its prepared Agent workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "RunLocalJobIdentityWire")]
pub struct RunLocalJobIdentity {
    /// Controller-generated lowercase UUID that names the prepared workspace.
    pub(crate) run_id: String,
    /// Content-addressed executable cache filename.
    pub(crate) candidate_name: String,
    /// SHA-256 of the executable bytes.
    pub(crate) candidate_sha256: String,
    /// Input files whose exact paths are derived from the run identity and environment names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mapped_files: Vec<RunLocalMappedFile>,
}

#[derive(Deserialize)]
pub(crate) struct RunLocalJobIdentityWire {
    run_id: String,
    candidate_name: String,
    candidate_sha256: String,
    #[serde(default)]
    mapped_files: Vec<RunLocalMappedFileWire>,
}

impl TryFrom<RunLocalJobIdentityWire> for RunLocalJobIdentity {
    type Error = String;

    fn try_from(value: RunLocalJobIdentityWire) -> Result<Self, Self::Error> {
        let mapped_files = value
            .mapped_files
            .into_iter()
            .map(RunLocalMappedFile::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::try_new(
            value.run_id,
            value.candidate_name,
            value.candidate_sha256,
            mapped_files,
        )
    }
}

impl RunLocalJobIdentity {
    /// Creates a validated durable local-candidate identity.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn try_new(
        run_id: String,
        candidate_name: String,
        candidate_sha256: String,
        mapped_files: Vec<RunLocalMappedFile>,
    ) -> Result<Self, String> {
        let value = Self {
            run_id,
            candidate_name,
            candidate_sha256,
            mapped_files,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates identity fields and rejects case-insensitive duplicate environment names.
    ///
    /// # Errors
    ///
    /// Returns a human-readable protocol validation error.
    pub fn validate(&self) -> Result<(), String> {
        if self.run_id.len() != 32
            || !self
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("run-local run_id must be 32 lowercase hexadecimal characters".to_owned());
        }
        validate_lowercase_sha256("run-local candidate", &self.candidate_sha256)?;
        if self.candidate_name.len() > 128
            || !valid_candidate_name(&self.candidate_name, &self.candidate_sha256)
        {
            return Err("run-local candidate name does not match its content digest".to_owned());
        }
        let mut names = BTreeSet::new();
        for mapped in &self.mapped_files {
            if !names.insert(mapped.environment_name.to_ascii_uppercase()) {
                return Err(format!(
                    "mapped run-local environment name {:?} is duplicated case-insensitively",
                    mapped.environment_name
                ));
            }
        }
        Ok(())
    }

    /// Returns the lowercase hexadecimal run identity.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the content-addressed executable cache filename.
    pub fn candidate_name(&self) -> &str {
        &self.candidate_name
    }

    /// Returns the lowercase SHA-256 digest of the executable bytes.
    pub fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    /// Returns the validated mapped input identities.
    pub fn mapped_files(&self) -> &[RunLocalMappedFile] {
        &self.mapped_files
    }
}

fn validate_lowercase_sha256(label: &str, digest: &str) -> Result<(), String> {
    if !is_lowercase_sha256(digest) {
        return Err(format!("{label} has invalid lowercase SHA-256"));
    }
    Ok(())
}

fn valid_candidate_name(name: &str, digest: &str) -> bool {
    let stem = format!("sha256-{digest}");
    if name == stem {
        return true;
    }
    name.strip_prefix(&stem)
        .and_then(|suffix| suffix.strip_prefix('.'))
        .is_some_and(|extension| {
            !extension.is_empty() && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

/// Durable execution state exposed by the resident agent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentJobState {
    /// Request is persisted but its worker has not started execution.
    Queued,
    /// Worker/process execution is currently active.
    Running,
    /// Process completed successfully.
    Succeeded,
    /// Process completed unsuccessfully.
    Failed,
    /// Cancellation was requested and execution was terminated.
    Canceled,
    /// Agent/runtime interruption prevented a proven normal completion.
    Interrupted,
}

impl AgentJobState {
    /// Returns whether no further normal state transition is expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Canceled | Self::Interrupted
        )
    }
}

/// Durable metadata describing one persistent agent job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "AgentJobInfoWire")]
pub struct AgentJobInfo {
    /// Stable agent-generated job identifier.
    pub job_id: String,
    /// Current durable state.
    pub state: AgentJobState,
    /// Agent worker process identifier when one has been created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_pid: Option<u32>,
    /// Agent process that owns the spawn transition while the job is still queued.
    /// Cleared after the detached worker publishes its PID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_owner_pid: Option<u32>,
    /// Root target process identifier when the child has started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,
    /// Target process exit code when terminal completion produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Job creation time as Unix milliseconds.
    pub created_unix_ms: u64,
    /// Execution start time as Unix milliseconds, when started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_unix_ms: Option<u64>,
    /// Terminal completion time as Unix milliseconds, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_unix_ms: Option<u64>,
    /// Optional bounded operator-facing state/failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Older durable stdout bytes were discarded because the bounded log reached its limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stdout_log_truncated: bool,
    /// Older durable stderr bytes were discarded because the bounded log reached its limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stderr_log_truncated: bool,
    /// Fully published result metadata after terminal completion, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_set: Option<ResultSetInfo>,
    /// Source-exact local-candidate ownership, absent for ordinary durable jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_local: Option<RunLocalJobIdentity>,
}

#[derive(Deserialize)]
struct AgentJobInfoWire {
    job_id: String,
    state: AgentJobState,
    #[serde(default)]
    worker_pid: Option<u32>,
    #[serde(default)]
    spawn_owner_pid: Option<u32>,
    #[serde(default)]
    process_pid: Option<u32>,
    #[serde(default)]
    exit_code: Option<i32>,
    created_unix_ms: u64,
    #[serde(default)]
    started_unix_ms: Option<u64>,
    #[serde(default)]
    finished_unix_ms: Option<u64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    stdout_log_truncated: bool,
    #[serde(default)]
    stderr_log_truncated: bool,
    #[serde(default)]
    result_set: Option<ResultSetInfo>,
    #[serde(default)]
    run_local: Option<RunLocalJobIdentity>,
}

impl TryFrom<AgentJobInfoWire> for AgentJobInfo {
    type Error = String;

    fn try_from(value: AgentJobInfoWire) -> Result<Self, Self::Error> {
        validate_result_set_id(&value.job_id)?;
        if let Some(result_set) = &value.result_set
            && result_set.owner().job_id() != Some(value.job_id.as_str())
        {
            return Err("durable result owner does not match enclosing job id".to_owned());
        }
        Ok(Self {
            job_id: value.job_id,
            state: value.state,
            worker_pid: value.worker_pid,
            spawn_owner_pid: value.spawn_owner_pid,
            process_pid: value.process_pid,
            exit_code: value.exit_code,
            created_unix_ms: value.created_unix_ms,
            started_unix_ms: value.started_unix_ms,
            finished_unix_ms: value.finished_unix_ms,
            message: value.message,
            stdout_log_truncated: value.stdout_log_truncated,
            stderr_log_truncated: value.stderr_log_truncated,
            result_set: value.result_set,
            run_local: value.run_local,
        })
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}
