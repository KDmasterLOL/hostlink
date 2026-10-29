//! Agent-local durable command queue and optional loopback board.
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

pub(crate) const MAX_ACTIVE_JOBS: usize = 16;
mod board;
mod database;
mod store;
mod worker;
pub use store::JobStore;
pub use worker::serve_until;

/// A direct executable invocation. No shell is implied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandJob {
    pub program: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[cfg(test)]
mod tests;
