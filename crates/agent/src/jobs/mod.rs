//! Agent-local durable command queue and optional loopback board.
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub const UPDATE_LOCK_FILE: &str = "update.lock";
pub(crate) const MAX_ACTIVE_JOBS: usize = 16;
mod board;
mod database;
mod private_fs;
mod store;
mod worker;
use private_fs::*;
pub(crate) use private_fs::{restrict_private_path, validate_private_path};
pub use store::{JobStore, active_ids};
pub use worker::serve_until;

/// A direct executable invocation. No shell is implied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandJob {
    pub program: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Lock the install root against concurrent update admission.
///
/// # Errors
/// Returns an error for an unsafe root or a failed lock.
pub fn acquire_update_lock(root: &Path) -> io::Result<File> {
    validate_private_path(root, true)?;
    let file = open_lock(&root.join(UPDATE_LOCK_FILE))?;
    file.lock()?;
    Ok(file)
}
#[cfg(test)]
mod tests;
