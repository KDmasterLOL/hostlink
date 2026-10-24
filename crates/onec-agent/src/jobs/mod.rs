//! Persistent structured jobs owned by the remote agent.
//!
//! Request/state persistence, streaming redaction, process lifecycle, and public job workflows are
//! separate owners so secret-handling and OS process semantics remain independently testable.

use crate::environment::{AgentEnvironmentPolicy, INTERNAL_JOB_SECRET_ENV, RequestedChildKind};
#[cfg(windows)]
use hostlink_core::configure_background_process_with_flags;
use hostlink_core::{
    ONEC_JOB_ID_ENV, ONEC_JOB_SYSTEM_ENV, RedactingWriter, RetainedLog,
    acquire_exclusive_file_lock, create_private_directory, ensure_private_directory,
    read_json_file_bounded, unix_time_ms as unix_ms, write_new_json_file, write_new_private_bytes,
};
use onec_agent_protocol::{
    AgentJobInfo, AgentJobState, ONEC_AGENT_JOB_SYSTEM, SecretEnvironment, StdinPayload,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
#[cfg(test)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

const JOB_SCHEMA_VERSION: u32 = 1;
const JOB_REQUEST_MAX_BYTES: usize = 1024 * 1024;
const JOB_STATE_MAX_BYTES: usize = 1024 * 1024;
const MAX_LOG_TAIL_BYTES: u64 = 64 * 1024;
pub const MAX_DURABLE_JOB_LOG_BYTES: u64 = 8 * 1024 * 1024;
const JOB_LOG_SEGMENT_BYTES: u64 = MAX_DURABLE_JOB_LOG_BYTES / 2;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Durable request/state and bounded log-tail DTOs.
mod model;
mod process;
mod redaction;
mod state;
/// Public durable-job start/status/log/cancel/worker orchestration.
mod workflow;

pub use model::JobLogTail;
pub(crate) use state::job_dir;
pub(crate) use workflow::{active_ids, recover_stale_jobs};
pub use workflow::{cancel, logs, run_worker, start_job, status, status_by_run_id};
pub(crate) use workflow::{
    ensure_run_local_not_abandoned, lock_run_local_identity, mark_run_local_abandoned,
    status_by_run_id_unlocked, validate_native_suite_policy_admission,
};

pub(crate) use model::{JobLaunchRequest, NativeInvocationCommitment};
use model::{JobProcessIdentities, JobRequestFile, JobStateFile};
use process::{ProcessIdentity, ProcessStatus, configure_detached_process, process_absent};
#[cfg(test)]
use redaction::DurableJobLogSink;
use redaction::{ProcesskitDurableJobLogSink, secret_patterns};
use state::*;

#[cfg(test)]
mod tests;
