//! Typed agent control responses.

use crate::{
    AgentJobInfo, NativeExecutionEffect, PROTOCOL_VERSION, ResultArtifactInfo, ResultSetInfo,
};
use serde::{Deserialize, Serialize};

/// Agent-observed run-local terminal success and owned cleanup statement.
///
/// This bounded statement does not assert a test inventory, source commit, toolchain identity,
/// or native lane. Unknown caller-supplied test outcome fields are rejected by the strict wire
/// schema. Those claims must be bound by a trusted runner completion protocol before release
/// acceptance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentTerminalExecutionRecord {
    /// Record schema version, currently 1.
    pub schema_version: u32,
    /// Fresh verifier challenge supplied with the authenticated request.
    pub challenge: String,
    /// Stable durable Agent job identifier.
    pub job_id: String,
    /// Controller-generated identity of the owned run-local workspace.
    pub run_id: String,
    /// Agent-validated SHA-256 of the staged executable.
    pub candidate_sha256: String,
    /// Terminal classification. Successful records always contain `succeeded`.
    pub command_completion: String,
    /// Terminal operating-system process exit code.
    pub command_exit_code: i32,
    /// Owned workspace cleanup classification. Successful records always contain `complete`.
    pub cleanup_completion: String,
    /// Opaque ID derived from the dedicated attestation public key.
    pub signer_id: String,
}

impl AgentTerminalExecutionRecord {
    /// Returns domain-separated, length-prefixed bytes covered by the Ed25519 signature.
    ///
    /// The JSON payload uses this struct's declared field order. The signature is carried beside
    /// the record and is not part of this payload.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the record cannot be encoded as JSON.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        const DOMAIN: &[u8] = b"onec-toolkit:agent:native-terminal:v1\0";
        let payload = serde_json::to_vec(self)?;
        let length = payload.len() as u64;
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 + payload.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
}

/// Agent-signed observation of one exact durable run-local invocation.
///
/// This record binds launch-request bytes by digest, the Agent-validated candidate digest,
/// caller-declared effect, host architecture/OS, terminal exit, and Agent-owned cleanup. It may
/// carry one exact testcase selector derived from argv; it does not assert a complete testcase
/// inventory, source commit, toolchain identity, or release lane.
/// Unknown caller-supplied suite outcome fields are rejected by the strict wire schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentNativeInvocationRecord {
    /// Record schema version, currently 1.
    pub schema_version: u32,
    /// Fresh verifier challenge supplied with the authenticated request.
    pub challenge: String,
    /// Stable durable Agent job identifier.
    pub job_id: String,
    /// Controller-generated identity of the owned run-local workspace.
    pub run_id: String,
    /// SHA-256 of the exact structured invocation persisted before worker spawn.
    pub invocation_sha256: String,
    /// Exact testcase filter requested with the canonical `--exact <name>` argument pair, when present.
    ///
    /// This binds one requested selector to the Agent-observed process exit. A zero exit does not
    /// prove that a matching testcase existed or ran; this does not assert a complete suite
    /// inventory or replace independent verification of the staged test binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_exact_testcase: Option<String>,
    /// Agent-validated SHA-256 of the staged executable.
    pub candidate_sha256: String,
    /// Caller-declared closed effect label persisted with the job before spawn.
    pub declared_effect: NativeExecutionEffect,
    /// Architecture of this Agent binary, such as `x86_64`.
    pub host_arch: String,
    /// Operating system of this Agent binary, such as `windows`.
    pub host_os: String,
    /// Terminal operating-system process exit code; successful records contain zero.
    pub command_exit_code: i32,
    /// Owned workspace cleanup classification; successful records contain `complete`.
    pub cleanup_completion: String,
    /// Opaque ID derived from the dedicated attestation public key.
    pub signer_id: String,
    /// Live Windows kernel/platform facts when this observation was made by a Windows Agent.
    ///
    /// Omitted from protocol-v1 canonical bytes when absent so signatures created before this
    /// field existed continue to verify unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_windows: Option<ObservedWindowsFacts>,
    /// Optional commitments to the complete Agent-owned durable output logs.
    ///
    /// Omitted from protocol-v1 canonical bytes for observations signed before output
    /// commitments were introduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_logs: Option<AgentNativeInvocationOutputLogs>,
    /// Optional immutable metadata for artifacts published by this invocation's durable job.
    ///
    /// Omitted from protocol-v1 canonical bytes for observations created before result-set
    /// commitments were introduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_set: Option<ResultSetInfo>,
}

/// SHA-256 commitments and retained byte lengths for one invocation's durable output logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentNativeInvocationOutputLogs {
    /// Lowercase SHA-256 of the complete Agent-owned `stdout.log` bytes.
    pub stdout_sha256: String,
    /// Complete retained stdout byte length.
    pub stdout_bytes: u64,
    /// Lowercase SHA-256 of the complete Agent-owned `stderr.log` bytes.
    pub stderr_sha256: String,
    /// Complete retained stderr byte length.
    pub stderr_bytes: u64,
}

/// Windows kernel/platform facts observed from live operating-system APIs by the Agent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedWindowsFacts {
    /// Kernel major version returned by `RtlGetVersion`.
    pub os_major: u32,
    /// Kernel minor version returned by `RtlGetVersion`.
    pub os_minor: u32,
    /// Kernel build number returned by `RtlGetVersion`.
    pub os_build: u32,
    /// Architecture reported for the current process by `GetSystemInfo`.
    pub process_architecture: WindowsArchitecture,
    /// Native machine architecture reported by `GetNativeSystemInfo`.
    pub native_architecture: WindowsArchitecture,
    /// Result reported by `IsWow64Process` for the current process.
    pub process_is_wow64: bool,
}

impl ObservedWindowsFacts {
    /// Checks that the observation is internally consistent with the Agent's host identity.
    pub fn is_consistent_with_host(&self, host_os: &str, host_arch: &str) -> bool {
        if host_os != "windows" || self.os_major < 6 || self.os_build == 0 {
            return false;
        }

        let process_arch = match self.process_architecture {
            WindowsArchitecture::X86 => "x86",
            WindowsArchitecture::X86_64 => "x86_64",
        };
        if host_arch != process_arch {
            return false;
        }

        match (self.process_architecture, self.native_architecture) {
            (WindowsArchitecture::X86, WindowsArchitecture::X86) => !self.process_is_wow64,
            (WindowsArchitecture::X86, WindowsArchitecture::X86_64) => self.process_is_wow64,
            (WindowsArchitecture::X86_64, WindowsArchitecture::X86_64) => !self.process_is_wow64,
            (WindowsArchitecture::X86_64, WindowsArchitecture::X86) => false,
        }
    }
}

/// Windows process or native-machine architecture supported by invocation observation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsArchitecture {
    /// 32-bit x86.
    X86,
    /// 64-bit x86-64.
    X86_64,
}

impl AgentNativeInvocationRecord {
    /// Returns domain-separated, length-prefixed bytes covered by the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the record cannot be encoded as JSON.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        const DOMAIN: &[u8] = b"onec-toolkit:agent:native-invocation:v1\0";
        let payload = serde_json::to_vec(self)?;
        let length = payload.len() as u64;
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 + payload.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }
}

/// Stable machine-readable error category for bounded immediate execution.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, strum::Display, strum::IntoStaticStr,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AgentErrorCode {
    /// Immediate execution requested an invalid timeout.
    ExecInvalidTimeout,
    /// Immediate child process could not be started.
    ExecStartFailed,
    /// Immediate process I/O/capture failed.
    ExecIoFailed,
    /// Immediate process exceeded its timeout.
    ExecTimeout,
    /// Captured output exceeded the immediate-exec protocol limit.
    ExecOutputLimit,
    /// Declared immediate-exec result artifacts violated publication policy.
    ExecResultInvalid,
    /// A typed result artifact could not be opened or streamed.
    ResultDownloadFailed,
    /// A typed result set could not be safely removed.
    ResultCleanupFailed,
    /// A requested filesystem path was proven absent by the agent.
    PathNotFound,
}

impl AgentErrorCode {
    /// Returns the stable wire-compatible snake-case identifier.
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// Versioned response envelope returned by one resident-agent request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentResponse {
    /// Protocol schema version.
    pub version: u32,
    /// Whether the request completed successfully.
    pub ok: bool,
    /// Typed success payload, present only on successful requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AgentResponseKind>,
    /// Human-readable failure text, present on failed requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional stable machine-readable error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<AgentErrorCode>,
}

impl AgentResponse {
    /// Creates a successful current-version response.
    pub fn success(response: AgentResponseKind) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: true,
            response: Some(response),
            error: None,
            error_code: None,
        }
    }

    /// Creates a failed current-version response without a stable error code.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: false,
            response: None,
            error: Some(error.into()),
            error_code: None,
        }
    }

    /// Creates a failed current-version response with a stable error code.
    pub fn failure_with_code(code: AgentErrorCode, error: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: false,
            response: None,
            error: Some(error.into()),
            error_code: Some(code),
        }
    }
}

/// Typed success payloads returned by resident-agent control operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponseKind {
    /// Agent identity/version/capability negotiation response.
    Hello {
        /// Configured logical agent name.
        name: String,
        /// Running agent package/version string.
        agent_version: String,
        /// Target operating-system hostname.
        hostname: String,
        /// Target operating-system identifier.
        os: String,
        /// Advertised optional control/runtime capabilities.
        #[serde(default)]
        capabilities: Vec<String>,
        /// Current agent executable path when discoverable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_executable: Option<String>,
        /// Current canonical `onec` controller executable path when discoverable.
        // Retain the old serialized field name for deployed protocol consumers.
        #[serde(
            default,
            rename = "onec_ops_executable",
            alias = "onec_executable",
            skip_serializing_if = "Option::is_none"
        )]
        onec_executable: Option<String>,
    },
    /// Result of one immediate bounded process execution.
    Exec {
        /// Child exit code when supplied by the operating system.
        exit_code: Option<i32>,
        /// Bounded captured standard output.
        stdout: String,
        /// Bounded captured standard error.
        stderr: String,
        /// Exact stdout bytes encoded as base64 when raw output was requested.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_base64: Option<String>,
        /// Exact stderr bytes encoded as base64 when raw output was requested.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stderr_base64: Option<String>,
        /// Fully published result metadata when this Exec declared artifacts.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result_set: Option<ResultSetInfo>,
    },
    /// Durable job was accepted/persisted for execution.
    JobStarted {
        /// Current durable job metadata.
        job: AgentJobInfo,
    },
    /// Current durable job metadata.
    JobStatus {
        /// Current durable job metadata.
        job: AgentJobInfo,
    },
    /// Bounded durable stdout/stderr tails plus truncation evidence.
    JobLogs {
        /// Stable job identifier.
        job_id: String,
        /// Requested bounded stdout tail.
        stdout: String,
        /// Requested bounded stderr tail.
        stderr: String,
        /// Requested stdout tail omitted older bytes.
        stdout_truncated: bool,
        /// Requested stderr tail omitted older bytes.
        stderr_truncated: bool,
        /// Durable storage itself discarded older stdout bytes.
        #[serde(default)]
        stdout_storage_truncated: bool,
        /// Durable storage itself discarded older stderr bytes.
        #[serde(default)]
        stderr_storage_truncated: bool,
    },
    /// Cancellation was requested and current durable metadata is returned.
    JobCancelRequested {
        /// Current durable job metadata.
        job: AgentJobInfo,
    },
    /// Requested TCP relay connection is established and ready for byte forwarding.
    TcpReady,
    /// Upload metadata was accepted and the binary upload stream may begin.
    UploadReady,
    /// Upload stream completed with the exact received byte count.
    Uploaded {
        /// Number of bytes accepted/published.
        bytes: u64,
    },
    /// Download metadata is validated and the binary stream will contain this many bytes.
    DownloadReady {
        /// Exact download byte count.
        bytes: u64,
    },
    /// Typed managed result is validated and its exact bytes follow on the binary stream.
    ResultDownloadReady {
        /// Immutable metadata that the controller must verify before local publication.
        artifact: ResultArtifactInfo,
    },
    /// Exact managed result set was removed or was already absent.
    ResultCleaned {
        /// Whether an existing owned result set was removed.
        removed: bool,
    },
    /// Exact path byte length and SHA-256 digest.
    PathSha256 {
        /// Hashed file byte length.
        bytes: u64,
        /// Lowercase hexadecimal SHA-256 digest.
        sha256: String,
    },
    /// Agent-owned persistent cache and per-run roots for `run-local`.
    RunLocalPaths {
        /// Persistent immutable executable cache root.
        cache_root: String,
        /// Parent root that bounds cleanup of one run state directory.
        run_root_parent: String,
        /// Unique directory owned by this run identity.
        run_root: String,
    },
    /// Public half of the dedicated native-attestation key.
    NativeAttestationPublicKey {
        /// Opaque SHA-256-derived signer ID.
        signer_id: String,
        /// Ed25519 verifying key in lowercase hexadecimal.
        verifying_key_hex: String,
    },
    /// Agent-signed terminal run-local success record.
    NativeExecutionAttestation {
        /// Agent-observed fields covered by the signature.
        record: AgentTerminalExecutionRecord,
        /// Ed25519 signature over the domain-separated canonical record payload.
        signature_hex: String,
    },
    /// Previously persisted attestation returned by the read-only recovery operation.
    NativeExecutionAttestationFetched {
        /// Agent-observed fields covered by the stored signature.
        record: AgentTerminalExecutionRecord,
        /// Stored Ed25519 signature; recovery never recomputes it.
        signature_hex: String,
    },
    /// Agent-signed exact invocation observation, without test inventory claims.
    NativeInvocationObservation {
        /// Agent-observed fields covered by the signature.
        record: AgentNativeInvocationRecord,
        /// Ed25519 signature over the domain-separated canonical record payload.
        signature_hex: String,
    },
    /// Previously persisted invocation observation returned by read-only recovery.
    NativeInvocationObservationFetched {
        /// Agent-observed fields covered by the stored signature.
        record: AgentNativeInvocationRecord,
        /// Stored Ed25519 signature; recovery never recomputes it.
        signature_hex: String,
    },
    /// Result of owned-root-scoped path removal.
    PathRemoved {
        /// Whether an existing target was removed.
        removed: bool,
    },
    /// Path rename/move completed successfully.
    PathRenamed,
}
