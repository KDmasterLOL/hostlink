//! Persisted job request/state and log-tail DTOs.

#![deny(clippy::missing_docs_in_private_items)]

use super::process::ProcessIdentity;
use super::*;
use hostlink_protocol::{NativeExecutionEffect, ResultArtifactSpec, RunLocalJobIdentity};

/// Non-secret durable-job launch inputs received from the authenticated control request.
pub(crate) struct JobLaunchRequest {
    /// Executable path or program name.
    pub(crate) program: String,
    /// Exact argv excluding `argv[0]`.
    pub(crate) args: Vec<String>,
    /// Optional working directory.
    pub(crate) cwd: Option<String>,
    /// Non-secret environment overlay.
    pub(crate) env: BTreeMap<String, String>,
    /// Optional exact non-secret stdin payload.
    pub(crate) stdin: Option<StdinPayload>,
    /// Declared target-owned result artifacts.
    pub(crate) results: Vec<ResultArtifactSpec>,
    /// Optional exact local-candidate/run-workspace identity.
    pub(crate) run_local: Option<RunLocalJobIdentity>,
    /// Closed caller-declared effect for a signed invocation observation.
    pub(crate) native_effect: Option<NativeExecutionEffect>,
    /// Optional digest of the independently pinned approved suite policy used for admission.
    pub(crate) native_suite_policy_sha256: Option<String>,
    /// Complete test inventory from the independently pinned native suite policy.
    pub(crate) native_suite_expected_tests: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Durable request payload written before spawning the detached job worker.
pub(super) struct JobRequestFile {
    /// Persisted request schema version.
    pub(super) version: u32,
    /// Executable path or program name.
    pub(super) program: String,
    /// Exact argv excluding `argv[0]`.
    pub(super) args: Vec<String>,
    /// Optional working directory.
    pub(super) cwd: Option<String>,
    /// Non-secret environment overlay.
    #[serde(default)]
    pub(super) env: BTreeMap<String, String>,
    /// Optional exact non-secret stdin payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) stdin: Option<StdinPayload>,
    /// Declared target-owned result artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) results: Vec<ResultArtifactSpec>,
    /// Optional exact local-candidate/run-workspace identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) run_local: Option<RunLocalJobIdentity>,
    /// SHA-256 commitment to the exact structured launch request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) invocation_sha256: Option<String>,
    /// Closed caller-declared effect for a signed invocation observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_effect: Option<NativeExecutionEffect>,
    /// Optional policy digest bound into the invocation commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_suite_policy_sha256: Option<String>,
    /// Complete test inventory from the independently pinned native suite policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_suite_expected_tests: Option<Vec<String>>,
}

/// Immutable commitment retained for the signed native invocation observation path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeInvocationCommitment {
    /// Commitment schema version.
    pub(crate) version: u32,
    /// SHA-256 of the exact structured invocation.
    pub(crate) invocation_sha256: String,
    /// Agent-derived exact testcase selector, when the launch argv contains one unambiguous pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requested_exact_testcase: Option<String>,
    /// Caller-declared closed effect label.
    pub(crate) native_effect: NativeExecutionEffect,
    /// Exact result declarations included in the pre-spawn invocation digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) results: Vec<ResultArtifactSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One immutable durable job-state snapshot.
pub(super) struct JobStateFile {
    /// Persisted state schema version.
    pub(super) version: u32,
    /// Public job state payload.
    pub(super) job: AgentJobInfo,
    /// OS process creation identities paired with the public PID fields.
    #[serde(default)]
    pub(super) process_identities: JobProcessIdentities,
}

/// Versioned process identity records for durable job ownership PIDs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct JobProcessIdentities {
    /// Identity bundle schema version; zero denotes a PID-only legacy state snapshot.
    #[serde(default)]
    pub(super) version: u32,
    /// Detached worker identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) worker: Option<ProcessIdentity>,
    /// Process that owns the queued launch handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) spawn_owner: Option<ProcessIdentity>,
    /// Command process supervised by the worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) process: Option<ProcessIdentity>,
}

/// Bounded log-tail response with caller-tail and durable-storage truncation evidence.
pub struct JobLogTail {
    /// Decoded stdout tail.
    pub stdout: String,
    /// Decoded stderr tail.
    pub stderr: String,
    /// Returned stdout does not contain every historical byte, either because the caller
    /// requested a tail or because bounded durable storage already discarded older bytes.
    pub stdout_truncated: bool,
    /// Returned stderr does not contain every historical byte, either because the caller
    /// requested a tail or because bounded durable storage already discarded older bytes.
    pub stderr_truncated: bool,
    /// Older durable stdout bytes were discarded by the storage bound.
    pub stdout_storage_truncated: bool,
    /// Older durable stderr bytes were discarded by the storage bound.
    pub stderr_storage_truncated: bool,
}
