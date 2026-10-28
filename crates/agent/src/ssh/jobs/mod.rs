//! Agent-owned durable execution over the frozen jobs-v1 SSH subsystem.

use super::config::invalid_data;
use super::*;

mod engine;
mod frame;
mod output;
mod protocol;
mod source;
mod wire;
mod worker;

pub(in crate::ssh) use engine::JobWorker;
pub(super) use frame::handle_job_channel;
pub(super) use source::verify_job_source;
pub(super) use worker::run_job;

pub(in crate::ssh) struct JobRuntime {
    pub(in crate::ssh) store: DurableStore,
    // Workers and sessions retain the runtime, so a dropped serve future cannot
    // release the exclusive recovery lease while an Agent-owned process lives.
    pub(in crate::ssh) _runner: std::fs::File,
    pub(in crate::ssh) start_lock: Mutex<()>,
    pub(in crate::ssh) slots: Arc<Semaphore>,
    pub(in crate::ssh) channel_slots: Arc<Semaphore>,
    pub(in crate::ssh) accepting: AtomicBool,
    pub(in crate::ssh) shutdown: processkit::CancellationToken,
    pub(in crate::ssh) active_jobs: std::sync::Mutex<HashMap<JobId, Arc<JobCancellation>>>,
}

/// Process cancellation is Agent-owned and unrelated to SSH channel lifetimes.
pub(in crate::ssh) struct JobCancellation {
    pub(in crate::ssh) process: processkit::CancellationToken,
    pub(in crate::ssh) requested: AtomicBool,
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod engine_tests;
