//! Shared JSON control protocol between the HostLink Agent and controller clients.
//!
//! The crate keeps a flat public API for compatibility while separating secret handling, request
//! and response schemas, persistent-job metadata, and bounded JSONL framing.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod digest;
mod framing;
mod invocation;
mod job;
mod request;
mod response;
mod result;
mod secret;
mod stdin;
mod suite;

/// Current JSON control-protocol schema version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum accepted size of one control-plane JSONL record.
pub const MAX_CONTROL_LINE_BYTES: usize = 1024 * 1024;
/// Default timeout for immediate `Exec` requests.
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 60_000;
/// Hard protocol ceiling for one immediate Exec request.
///
/// Generic `exec` keeps the shorter default above. Cargo/Nextest target runners use this ceiling
/// as an outer transport bound while Nextest owns the earlier per-test timeout. Keep this value
/// wire-compatible with maintained deployed agents; long native scenarios must be decomposed or
/// use a lifecycle designed for long-running jobs rather than widening immediate Exec in place.
pub const MAX_EXEC_TIMEOUT_MS: u64 = 10 * 60 * 1000;
/// Legacy correlation environment key retained for deployed protocol consumers.
pub const ONEC_PARENT_RUN_ID_ENV: &str = "ONEC_PARENT_RUN_ID";
/// Legacy durable-job system environment key retained for deployed protocol consumers.
pub const ONEC_JOB_SYSTEM_ENV: &str = "ONEC_JOB_SYSTEM";
/// Legacy durable-job identity environment key retained for deployed protocol consumers.
pub const ONEC_JOB_ID_ENV: &str = "ONEC_JOB_ID";
/// Legacy result directory environment key retained for deployed protocol consumers.
pub const ONEC_RESULT_DIR_ENV: &str = "ONEC_RESULT_DIR";

/// Agent-owned durable-job namespace placed in the job-system correlation environment.
pub const ONEC_AGENT_JOB_SYSTEM: &str = "onec_agent_job";

pub use framing::{read_json_line, write_json_line};
pub use invocation::{NativeInvocationIdentity, requested_exact_testcase};
pub use job::{
    AgentJobInfo, AgentJobState, NativeExecutionEffect, RunLocalJobIdentity, RunLocalMappedFile,
};
pub use request::{
    AgentRequest, AgentRequestKind, AgentRequestValidationError, AgentRequestValidationKind,
    decode_agent_request,
};
pub use response::{
    AgentErrorCode, AgentNativeInvocationOutputLogs, AgentNativeInvocationRecord, AgentResponse,
    AgentResponseKind, AgentTerminalExecutionRecord, ObservedWindowsFacts, WindowsArchitecture,
};
pub use result::{
    MAX_RESULT_ARTIFACT_BYTES, MAX_RESULT_ARTIFACTS, MAX_RESULT_MEDIA_TYPE_BYTES,
    MAX_RESULT_NAME_BYTES, MAX_RESULT_SET_BYTES, MAX_RESULT_SET_ID_BYTES, ResultArtifactInfo,
    ResultArtifactSpec, ResultOwner, ResultSetInfo, validate_result_name, validate_result_set_id,
    validate_result_specs,
};
pub use secret::SecretEnvironment;
pub use stdin::{MAX_STDIN_PAYLOAD_BYTES, StdinPayload, StdinPayloadTooLarge};
pub use suite::NativeSuitePolicy;

#[cfg(test)]
mod tests;
