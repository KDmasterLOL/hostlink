//! Authenticated embedded russh server for short exec, SFTP, and direct TCP forwarding.

use crate::{
    AgentConfig,
    durable::{self, Admission, DurableStore, JobId, JobOutput, JobSpec, JobState},
    exec,
    sftp::SftpSession,
};
use russh::keys::ssh_key::authorized_keys::AuthorizedKeys;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};

const HOST_KEY_MAX_BYTES: usize = 64 * 1024;
const AUTHORIZED_KEYS_MAX_BYTES: usize = 1024 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIRECT_TCP_CHANNELS: usize = 32;
const MAX_AUTHENTICATED_SESSIONS: usize = 32;
const MAX_ACTIVE_SFTP_SESSIONS: usize = 8;
const MAX_ACTIVE_EXEC_SESSIONS: usize = 4;
const MAX_PENDING_SESSION_CHANNELS: usize = 16;
const MAX_EXEC_COMMAND_BYTES: usize = 16 * 1024;
const JOB_SUBSYSTEM: &str = "hostlink-jobs-v1";
const JOB_FRAME_MAX_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_JOBS: usize = 16;
const MAX_JOB_CHANNELS: usize = 32;
#[cfg(not(test))]
const JOB_TIMEOUT: Duration = Duration::from_secs(15 * 60);
#[cfg(test)]
const JOB_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

mod config;
mod jobs;
mod server;

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/durable_unix.rs"]
mod durable_job_tests;
#[cfg(all(test, unix))]
#[path = "tests/source.rs"]
mod job_source_tests;
#[cfg(all(test, windows))]
#[path = "tests/durable_windows.rs"]
mod windows_durable_job_tests;

pub(crate) use config::validate_private_path;
pub use server::{serve, serve_on};
