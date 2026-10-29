//! Source-pinned durable job identities, private state and update admission guards.
//!
//! Apalis SQLite is the sole record owner; filesystem paths contain only raw output.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
#[cfg(test)]
use std::io::Write;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(crate) const WORKER_NAME: &str = "hostlink-agent-worker";

const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_JOBS: usize = 4096;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_ARTIFACTS_PER_CONTROLLER: usize = 128;
pub(crate) const MAX_JOB_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_OUTPUT_CHUNK_BYTES: usize = 24 * 1024;

/// A shared file lock: job admission and Agent update must exclude one another.
pub const UPDATE_LOCK_FILE: &str = "update.lock";

mod artifacts;
mod database;
mod inventory;
mod lifecycle;
mod query;
pub use query::JobSummary;
mod model;
mod output;
mod persistence;
mod private_fs;

pub(crate) use artifacts::ArtifactStore;
pub use inventory::active_ids;
pub use model::JobPayload;
pub use model::{JobId, JobSpec, JobState, JobView};
use output::*;
pub(crate) use output::{JobOutput, open_output_append};
pub use persistence::JobStore;
pub use private_fs::acquire_update_lock;
use private_fs::*;
pub(crate) use private_fs::{restrict_private_path, validate_private_path};

#[cfg(test)]
mod tests;

use private_fs::invalid as invalid_data;
use russh::{Channel, server::Msg};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, Semaphore},
};

pub(crate) const MAX_ACTIVE_JOBS: usize = 16;
pub(crate) const MAX_JOB_CHANNELS: usize = 32;
const JOB_FRAME_MAX_BYTES: usize = 64 * 1024;
const JOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const JOB_TIMEOUT: Duration = Duration::from_secs(15 * 60);
#[cfg(test)]
const JOB_TIMEOUT: Duration = Duration::from_secs(30);

mod engine;
mod frame;
mod protocol;
mod source;
mod spool;
mod worker;
pub(crate) use engine::JobWorker;
pub(crate) use frame::handle_job_channel;
use source::verify_job_source;
use worker::run_job;

pub(crate) struct JobRuntime {
    pub(crate) store: JobStore,
    // Retained by process tasks through complete teardown, even if SSH stops.
    pub(crate) _runner: File,
    pub(crate) start_lock: Mutex<()>,
    // Tower bounds active consume futures; this semaphore instead tracks OS
    // process-tree lifetimes and remains held through UNKNOWN/quarantine.
    pub(crate) slots: Arc<Semaphore>,
    pub(crate) channel_slots: Arc<Semaphore>,
    pub(crate) accepting: AtomicBool,
    pub(crate) shutdown: processkit::CancellationToken,
    pub(crate) active_jobs: std::sync::Mutex<HashMap<JobId, processkit::CancellationToken>>,
    pub(crate) unknown_permits: std::sync::Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>,
}

impl JobRuntime {
    /// Open an established jobs root and own its exclusive Agent runtime lease.
    ///
    /// Opening, recovery and runtime construction stay together so SSH only
    /// receives a fully recovered, exclusively owned jobs subsystem.
    pub(crate) async fn open(jobs_root: &Path) -> io::Result<Arc<Self>> {
        let store = JobStore::open(jobs_root).await?;
        let runner = store.acquire_runner()?;
        Ok(Arc::new(Self {
            store,
            _runner: runner,
            start_lock: Mutex::new(()),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
            channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
            accepting: AtomicBool::new(true),
            shutdown: processkit::CancellationToken::new(),
            active_jobs: std::sync::Mutex::new(HashMap::new()),
            unknown_permits: std::sync::Mutex::new(Vec::new()),
        }))
    }
}

impl Drop for JobRuntime {
    fn drop(&mut self) {
        // The last Arc is dropped only after every retained worker/process
        // task releases runtime ownership. Explicitly unlock the lease rather
        // than relying on close: a concurrent child may have inherited its FD.
        if let Err(error) = self._runner.unlock() {
            eprintln!("hostlink-agent: could not release durable runner lease: {error}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod engine_tests;
#[cfg(all(test, target_os = "linux"))]
mod protocol_tests;

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod process_tests;
#[cfg(all(test, unix))]
mod source_tests;
#[cfg(all(test, windows))]
mod windows_process_tests;

#[cfg(windows)]
pub(crate) use private_fs::secure_new_upload;
