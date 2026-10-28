//! Source-pinned durable job identities, private state and update admission guards.
//!
//! Apalis SQLite is the sole record owner; filesystem paths contain only raw output.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) const WORKER_NAME: &str = "hostlink-agent-worker-v1";

const SCHEMA_VERSION: u32 = 1;
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
mod model;
mod output;
mod persistence;
mod private_fs;

pub(crate) use artifacts::ArtifactStore;
pub use inventory::active_ids;
pub use model::{Admission, JobId, JobRecord, JobSpec, JobState};
use output::*;
pub(crate) use output::{JobOutput, open_output_append};
pub use persistence::DurableStore;
pub use private_fs::acquire_update_lock;
use private_fs::*;
pub(crate) use private_fs::{restrict_private_path, validate_private_path};

#[cfg(test)]
mod tests;
