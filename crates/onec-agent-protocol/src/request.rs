//! Typed agent control requests and protocol-default request fields.

use crate::job::{NativeExecutionEffect, RunLocalJobIdentityWire};
use crate::result::{ResultArtifactSpecWire, ResultOwnerWire};
use crate::{
    NativeSuitePolicy, PROTOCOL_VERSION, ResultArtifactSpec, ResultOwner, RunLocalJobIdentity,
    SecretEnvironment, StdinPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Versioned authenticated control request sent to one resident agent.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "AgentRequestWire")]
pub struct AgentRequest {
    /// Protocol schema version.
    pub version: u32,
    /// Agent control authentication token.
    pub token: String,
    /// Typed operation payload.
    pub request: AgentRequestKind,
}

impl std::fmt::Debug for AgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the entire request payload out of envelope-level diagnostics:
        // Exec/JobStart args and the nominally non-secret env overlay can contain
        // operator-supplied credentials even though secret_env itself is redacted.
        f.debug_struct("AgentRequest")
            .field("version", &self.version)
            .field("token", &"[REDACTED]")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

/// Semantic validation category for a syntactically valid but invalid control request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRequestValidationKind {
    /// Immediate Exec result declarations are invalid.
    ExecResults,
    /// Durable JobStart result declarations are invalid.
    JobStartResults,
    /// Durable JobStart run-local identity is invalid.
    JobStartRunLocalIdentity,
    /// Invocation observation request is invalid.
    NativeInvocationObservation,
    /// Result download owner identity is invalid.
    ResultDownloadOwner,
    /// Result cleanup owner identity is invalid.
    ResultCleanupOwner,
}

/// Typed validation failure from a fully decoded request envelope.
pub struct AgentRequestValidationError {
    version: u32,
    token: String,
    kind: AgentRequestValidationKind,
    message: String,
}

impl AgentRequestValidationError {
    /// Returns the semantic validation category.
    pub fn kind(&self) -> AgentRequestValidationKind {
        self.kind
    }

    /// Returns validation detail without exposing envelope credentials.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The envelope protocol version. It is not a credential.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Compares the presented token without leaking its contents.
    pub fn matches_token(&self, expected_token: &str) -> bool {
        onec_core::constant_time_str_eq(&self.token, expected_token)
    }
}

impl std::fmt::Debug for AgentRequestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRequestValidationError")
            .field("version", &self.version)
            .field("token", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl std::fmt::Display for AgentRequestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentRequestValidationError {}

#[derive(Debug)]
struct RequestKindValidationError {
    kind: AgentRequestValidationKind,
    message: String,
}

impl std::fmt::Display for RequestKindValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Deserialize)]
struct AgentRequestWire {
    version: u32,
    token: String,
    request: AgentRequestKindWire,
}

impl TryFrom<AgentRequestWire> for AgentRequest {
    type Error = AgentRequestValidationError;

    fn try_from(value: AgentRequestWire) -> Result<Self, Self::Error> {
        let request = AgentRequestKind::try_from(value.request).map_err(|error| {
            AgentRequestValidationError {
                version: value.version,
                token: value.token.clone(),
                kind: error.kind,
                message: error.message,
            }
        })?;
        Ok(Self {
            version: value.version,
            token: value.token,
            request,
        })
    }
}

/// Decodes one typed request and retains semantic failure categories for the control boundary.
///
/// The outer error indicates malformed JSON or request shape. The inner error indicates a fully
/// decoded envelope whose operation-specific value failed semantic validation.
pub fn decode_agent_request(
    json: &[u8],
) -> Result<Result<AgentRequest, AgentRequestValidationError>, serde_json::Error> {
    let wire: AgentRequestWire = serde_json::from_slice(json)?;
    Ok(wire.try_into())
}

impl AgentRequest {
    /// Creates a request using the current protocol version.
    pub fn new(token: impl Into<String>, request: AgentRequestKind) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            token: token.into(),
            request,
        }
    }
}

/// Supported resident-agent control operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    try_from = "AgentRequestKindWire"
)]
pub enum AgentRequestKind {
    /// Negotiate agent identity/version/capabilities.
    Hello,
    /// Run one bounded immediate child process and return captured output.
    Exec {
        /// Executable path/name.
        program: String,
        /// Exact child argument vector.
        #[serde(default)]
        args: Vec<String>,
        /// Optional child working directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Non-secret explicit child environment overlay.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        /// Secret child environment overlay with redacted debug formatting.
        #[serde(default, skip_serializing_if = "SecretEnvironment::is_empty")]
        secret_env: SecretEnvironment,
        /// Optional exact non-secret stdin bytes. None means no stdin payload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<StdinPayload>,
        /// Opaque caller-known result-set identifier when result artifacts are declared.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result_set_id: Option<String>,
        /// Declared target-owned result files written under ONEC_RESULT_DIR.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        results: Vec<ResultArtifactSpec>,
        /// Maximum execution time before the owned child tree is terminated.
        #[serde(default = "default_exec_timeout_ms")]
        timeout_ms: u64,
        /// Include exact captured output bytes as base64 for byte-preserving callers.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        raw_output: bool,
    },
    /// Persist and start a reconnectable durable target process.
    JobStart {
        /// Executable path/name.
        program: String,
        /// Exact child argument vector.
        #[serde(default)]
        args: Vec<String>,
        /// Optional child working directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Non-secret explicit child environment overlay.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        /// Secret child environment overlay.
        #[serde(default, skip_serializing_if = "SecretEnvironment::is_empty")]
        secret_env: SecretEnvironment,
        /// Optional exact non-secret stdin bytes. None means no stdin payload.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<StdinPayload>,
        /// Declared target-owned result files written under ONEC_RESULT_DIR.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        results: Vec<ResultArtifactSpec>,
        /// Optional run-local candidate/workspace ownership binding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_local: Option<RunLocalJobIdentity>,
    },
    /// Start a run-local candidate job with an immutable invocation observation commitment.
    NativeRunLocalJobStart {
        /// Executable path/name.
        program: String,
        /// Exact child argument vector.
        #[serde(default)]
        args: Vec<String>,
        /// Optional child working directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Non-secret explicit child environment overlay.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        /// Secret environment is prohibited for signed invocation observations.
        #[serde(default, skip_serializing_if = "SecretEnvironment::is_empty")]
        secret_env: SecretEnvironment,
        /// Optional exact non-secret stdin bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin: Option<StdinPayload>,
        /// Declared target-owned result files written under ONEC_RESULT_DIR.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        results: Vec<ResultArtifactSpec>,
        /// Required source-exact local-candidate/workspace identity.
        run_local: RunLocalJobIdentity,
        /// Closed caller-declared effect label, checked against independent consumer policy.
        native_effect: NativeExecutionEffect,
        /// Optional approved suite policy checked against the Agent's independent configuration pin.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        native_suite_policy: Option<NativeSuitePolicy>,
    },
    /// Read durable metadata for one job.
    JobStatus {
        /// Stable job identifier.
        job_id: String,
    },
    /// Read bounded tails of durable job stdout/stderr.
    JobLogs {
        /// Stable job identifier.
        job_id: String,
        /// Maximum bytes requested from each logical log tail.
        #[serde(default = "default_job_log_tail_bytes")]
        tail_bytes: u64,
    },
    /// Request cancellation of one durable job.
    JobCancel {
        /// Stable job identifier.
        job_id: String,
    },
    /// Stream one fully published managed result by logical owner and name.
    ResultDownload {
        /// Opaque typed result owner; physical target paths are never accepted here.
        owner: ResultOwner,
        /// Portable logical artifact name.
        name: String,
    },
    /// Remove one complete managed result set by logical owner.
    ResultCleanup {
        /// Opaque typed result owner; physical target paths are never accepted here.
        owner: ResultOwner,
    },
    /// Ask the target to establish one outbound TCP connection for relay.
    TcpConnect {
        /// Destination hostname/address.
        host: String,
        /// Destination TCP port.
        port: u16,
        /// Maximum connect time in milliseconds.
        #[serde(default = "default_connect_timeout_ms")]
        timeout_ms: u64,
    },
    /// Prepare an upload to one target path.
    Upload {
        /// Target path governed by agent filesystem policy.
        path: String,
        /// Exact byte count that the binary transfer must contain.
        bytes: u64,
        /// Whether an existing target may be replaced.
        #[serde(default)]
        overwrite: bool,
    },
    /// Prepare download of one target file.
    Download {
        /// Target path governed by agent filesystem policy.
        path: String,
    },
    /// Hash one target file/path using the agent's filesystem owner.
    PathSha256 {
        /// Target path to hash.
        path: String,
    },
    /// Prepare toolkit-owned persistent cache and identity-owned run state paths.
    RunLocalPrepare {
        /// Controller-generated lowercase UUID run identity.
        run_id: String,
        /// Create the mapped-input subdirectory for a durable local-candidate job.
        #[serde(default, skip_serializing_if = "is_false")]
        create_mapped_workspace: bool,
    },
    /// Reconnect to a durable run-local job using its controller-generated run identity.
    RunLocalStatus {
        /// Controller-generated run identity persisted in the job metadata.
        run_id: String,
    },
    /// Sign observed success for one terminal run-local job after its owned workspace is removed.
    RunLocalAttest {
        /// Stable durable Agent job identifier.
        job_id: String,
        /// Fresh verifier challenge, pinned out of band by the evidence consumer.
        challenge: String,
    },
    /// Read one already-created attestation without creating keys or signing again.
    RunLocalAttestationFetch {
        /// Stable durable Agent job identifier.
        job_id: String,
        /// Exact challenge originally supplied to the one-shot signing request.
        challenge: String,
    },
    /// Sign one successful run-local invocation commitment after result retrieval and cleanup.
    RunLocalInvocationObserve {
        /// Stable durable Agent job identifier.
        job_id: String,
        /// Fresh verifier challenge, pinned out of band by the evidence consumer.
        challenge: String,
        /// Expected SHA-256 invocation commitment independently retained by the consumer.
        invocation_sha256: String,
    },
    /// Read one previously persisted invocation observation without signing again.
    RunLocalInvocationObservationFetch {
        /// Stable durable Agent job identifier.
        job_id: String,
        /// Exact challenge originally supplied to the one-shot signing request.
        challenge: String,
        /// Exact invocation commitment originally supplied to the signing request.
        invocation_sha256: String,
    },
    /// Export the public half of the agent-native-attestation key for out-of-band enrollment.
    NativeAttestationPublicKey,
    /// Finalize one terminal run-local job and remove only its prepared workspace.
    RunLocalFinalize {
        /// Stable durable Agent job identifier.
        job_id: String,
    },
    /// Remove a prepared run-local workspace when JobStart did not create a job.
    RunLocalAbandon {
        /// Controller-generated run identity naming the exact prepared workspace.
        run_id: String,
    },
    /// Remove a path only when it is structurally contained by an owned root.
    PathRemoveScoped {
        /// Declared owned root that bounds deletion authority.
        root: String,
        /// Descendant path requested for removal.
        path: String,
        /// Whether directory-tree removal is permitted.
        #[serde(default)]
        recursive: bool,
        /// Whether an absent target is treated as success.
        #[serde(default)]
        missing_ok: bool,
    },
    /// Rename/move one target path under agent filesystem policy.
    PathRename {
        /// Existing source path.
        from: String,
        /// Destination path.
        to: String,
        /// Whether an existing destination may be replaced.
        #[serde(default)]
        overwrite: bool,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AgentRequestKindWire {
    Hello,
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        secret_env: SecretEnvironment,
        #[serde(default)]
        stdin: Option<StdinPayload>,
        #[serde(default)]
        result_set_id: Option<String>,
        #[serde(default)]
        results: Vec<ResultArtifactSpecWire>,
        #[serde(default = "default_exec_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        raw_output: bool,
    },
    JobStart {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        secret_env: SecretEnvironment,
        #[serde(default)]
        stdin: Option<StdinPayload>,
        #[serde(default)]
        results: Vec<ResultArtifactSpecWire>,
        #[serde(default)]
        run_local: Option<RunLocalJobIdentityWire>,
    },
    NativeRunLocalJobStart {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        secret_env: SecretEnvironment,
        #[serde(default)]
        stdin: Option<StdinPayload>,
        #[serde(default)]
        results: Vec<ResultArtifactSpecWire>,
        run_local: RunLocalJobIdentityWire,
        native_effect: NativeExecutionEffect,
        #[serde(default)]
        native_suite_policy: Option<NativeSuitePolicy>,
    },
    JobStatus {
        job_id: String,
    },
    JobLogs {
        job_id: String,
        #[serde(default = "default_job_log_tail_bytes")]
        tail_bytes: u64,
    },
    JobCancel {
        job_id: String,
    },
    ResultDownload {
        owner: ResultOwnerWire,
        name: String,
    },
    ResultCleanup {
        owner: ResultOwnerWire,
    },
    TcpConnect {
        host: String,
        port: u16,
        #[serde(default = "default_connect_timeout_ms")]
        timeout_ms: u64,
    },
    Upload {
        path: String,
        bytes: u64,
        #[serde(default)]
        overwrite: bool,
    },
    Download {
        path: String,
    },
    PathSha256 {
        path: String,
    },
    RunLocalPrepare {
        run_id: String,
        #[serde(default)]
        create_mapped_workspace: bool,
    },
    RunLocalStatus {
        run_id: String,
    },
    RunLocalAttest {
        job_id: String,
        challenge: String,
    },
    RunLocalAttestationFetch {
        job_id: String,
        challenge: String,
    },
    RunLocalInvocationObserve {
        job_id: String,
        challenge: String,
        invocation_sha256: String,
    },
    RunLocalInvocationObservationFetch {
        job_id: String,
        challenge: String,
        invocation_sha256: String,
    },
    NativeAttestationPublicKey,
    RunLocalFinalize {
        job_id: String,
    },
    RunLocalAbandon {
        run_id: String,
    },
    PathRemoveScoped {
        root: String,
        path: String,
        #[serde(default)]
        recursive: bool,
        #[serde(default)]
        missing_ok: bool,
    },
    PathRename {
        from: String,
        to: String,
        #[serde(default)]
        overwrite: bool,
    },
}

impl TryFrom<AgentRequestKindWire> for AgentRequestKind {
    type Error = RequestKindValidationError;

    fn try_from(value: AgentRequestKindWire) -> Result<Self, Self::Error> {
        let validate_specs = |wire_specs: Vec<ResultArtifactSpecWire>, kind| {
            let specs = wire_specs
                .into_iter()
                .map(ResultArtifactSpec::try_from)
                .collect::<Result<Vec<_>, String>>()
                .map_err(|message| RequestKindValidationError { kind, message })?;
            crate::validate_result_specs(&specs)
                .map_err(|message| RequestKindValidationError { kind, message })?;
            Ok::<_, RequestKindValidationError>(specs)
        };
        Ok(match value {
            AgentRequestKindWire::Hello => Self::Hello,
            AgentRequestKindWire::Exec {
                program,
                args,
                cwd,
                env,
                secret_env,
                stdin,
                result_set_id,
                results,
                timeout_ms,
                raw_output,
            } => Self::Exec {
                program,
                args,
                cwd,
                env,
                secret_env,
                stdin,
                result_set_id,
                results: validate_specs(results, AgentRequestValidationKind::ExecResults)?,
                timeout_ms,
                raw_output,
            },
            AgentRequestKindWire::JobStart {
                program,
                args,
                cwd,
                env,
                secret_env,
                stdin,
                results,
                run_local,
            } => Self::JobStart {
                program,
                args,
                cwd,
                env,
                secret_env,
                stdin,
                results: validate_specs(results, AgentRequestValidationKind::JobStartResults)?,
                run_local: run_local
                    .map(RunLocalJobIdentity::try_from)
                    .transpose()
                    .map_err(|message| RequestKindValidationError {
                        kind: AgentRequestValidationKind::JobStartRunLocalIdentity,
                        message,
                    })?,
            },
            AgentRequestKindWire::NativeRunLocalJobStart {
                program,
                args,
                cwd,
                env,
                secret_env,
                stdin,
                results,
                run_local,
                native_effect,
                native_suite_policy,
            } => {
                if !secret_env.is_empty() {
                    return Err(RequestKindValidationError {
                        kind: AgentRequestValidationKind::NativeInvocationObservation,
                        message: "native invocation observation does not accept secret environment"
                            .to_owned(),
                    });
                }
                Self::NativeRunLocalJobStart {
                    program,
                    args,
                    cwd,
                    env,
                    secret_env,
                    stdin,
                    results: validate_specs(results, AgentRequestValidationKind::JobStartResults)?,
                    run_local: RunLocalJobIdentity::try_from(run_local).map_err(|message| {
                        RequestKindValidationError {
                            kind: AgentRequestValidationKind::JobStartRunLocalIdentity,
                            message,
                        }
                    })?,
                    native_effect,
                    native_suite_policy,
                }
            }
            AgentRequestKindWire::JobStatus { job_id } => Self::JobStatus { job_id },
            AgentRequestKindWire::JobLogs { job_id, tail_bytes } => {
                Self::JobLogs { job_id, tail_bytes }
            }
            AgentRequestKindWire::JobCancel { job_id } => Self::JobCancel { job_id },
            AgentRequestKindWire::ResultDownload { owner, name } => Self::ResultDownload {
                owner: ResultOwner::try_from(owner).map_err(|message| {
                    RequestKindValidationError {
                        kind: AgentRequestValidationKind::ResultDownloadOwner,
                        message,
                    }
                })?,
                name,
            },
            AgentRequestKindWire::ResultCleanup { owner } => Self::ResultCleanup {
                owner: ResultOwner::try_from(owner).map_err(|message| {
                    RequestKindValidationError {
                        kind: AgentRequestValidationKind::ResultCleanupOwner,
                        message,
                    }
                })?,
            },
            AgentRequestKindWire::TcpConnect {
                host,
                port,
                timeout_ms,
            } => Self::TcpConnect {
                host,
                port,
                timeout_ms,
            },
            AgentRequestKindWire::Upload {
                path,
                bytes,
                overwrite,
            } => Self::Upload {
                path,
                bytes,
                overwrite,
            },
            AgentRequestKindWire::Download { path } => Self::Download { path },
            AgentRequestKindWire::PathSha256 { path } => Self::PathSha256 { path },
            AgentRequestKindWire::RunLocalPrepare {
                run_id,
                create_mapped_workspace,
            } => Self::RunLocalPrepare {
                run_id,
                create_mapped_workspace,
            },
            AgentRequestKindWire::RunLocalStatus { run_id } => Self::RunLocalStatus { run_id },
            AgentRequestKindWire::RunLocalAttest { job_id, challenge } => {
                Self::RunLocalAttest { job_id, challenge }
            }
            AgentRequestKindWire::RunLocalAttestationFetch { job_id, challenge } => {
                Self::RunLocalAttestationFetch { job_id, challenge }
            }
            AgentRequestKindWire::RunLocalInvocationObserve {
                job_id,
                challenge,
                invocation_sha256,
            } => validate_native_observation(job_id, challenge, invocation_sha256, true)?,
            AgentRequestKindWire::RunLocalInvocationObservationFetch {
                job_id,
                challenge,
                invocation_sha256,
            } => validate_native_observation(job_id, challenge, invocation_sha256, false)?,
            AgentRequestKindWire::NativeAttestationPublicKey => Self::NativeAttestationPublicKey,
            AgentRequestKindWire::RunLocalFinalize { job_id } => Self::RunLocalFinalize { job_id },
            AgentRequestKindWire::RunLocalAbandon { run_id } => Self::RunLocalAbandon { run_id },
            AgentRequestKindWire::PathRemoveScoped {
                root,
                path,
                recursive,
                missing_ok,
            } => Self::PathRemoveScoped {
                root,
                path,
                recursive,
                missing_ok,
            },
            AgentRequestKindWire::PathRename {
                from,
                to,
                overwrite,
            } => Self::PathRename {
                from,
                to,
                overwrite,
            },
        })
    }
}

fn validate_native_observation(
    job_id: String,
    challenge: String,
    invocation_sha256: String,
    sign: bool,
) -> Result<AgentRequestKind, RequestKindValidationError> {
    let valid_job_id = job_id.starts_with("job-")
        && job_id.len() <= 128
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    let valid_digest = invocation_sha256.len() == 64
        && invocation_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_job_id || challenge.is_empty() || challenge.len() > 128 || !valid_digest {
        return Err(RequestKindValidationError {
            kind: AgentRequestValidationKind::NativeInvocationObservation,
            message: "native invocation observation identity is invalid".to_owned(),
        });
    }
    Ok(if sign {
        AgentRequestKind::RunLocalInvocationObserve {
            job_id,
            challenge,
            invocation_sha256,
        }
    } else {
        AgentRequestKind::RunLocalInvocationObservationFetch {
            job_id,
            challenge,
            invocation_sha256,
        }
    })
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_exec_timeout_ms() -> u64 {
    crate::DEFAULT_EXEC_TIMEOUT_MS
}

fn default_job_log_tail_bytes() -> u64 {
    64 * 1024
}

fn default_connect_timeout_ms() -> u64 {
    5000
}
