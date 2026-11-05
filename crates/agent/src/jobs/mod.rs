//! Agent-local durable command queue and optional loopback board.
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

pub(crate) const MAX_ACTIVE_JOBS: usize = 16;
const DEFAULT_COMMAND_TIMEOUT_SECONDS: u64 = 900;
const MAX_COMMAND_TIMEOUT_SECONDS: u64 = 14_400;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

fn command_timeout_seconds(timeout_seconds: Option<u64>) -> io::Result<u64> {
    let seconds = timeout_seconds.unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECONDS);
    if !(1..=MAX_COMMAND_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command timeout must be between 1 and 14400 seconds",
        ));
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests;
