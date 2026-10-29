//! Authenticated embedded russh server for short exec, SFTP, and direct TCP forwarding.

use crate::{AgentConfig, exec, sftp::SftpSession};
use russh::keys::ssh_key::authorized_keys::AuthorizedKeys;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
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

mod config;

mod server;

pub(crate) use config::validate_private_path;
pub use server::{serve, serve_on};
