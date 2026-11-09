//! Optional pinned reverse SSH connection to an approved gateway.
use crate::{AgentConfig, ReverseGateway};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

const MAX_FORWARDS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(60);
const STABLE_SESSION_RESET: Duration = Duration::from_secs(60);
const MAX_JITTER_PERCENT: u128 = 25;
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

mod retry;
mod session;
use retry::{
    AttemptFailure, AttemptPhase, emit_diagnostic, error_class, jitter_cap_ms,
    reset_backoff_after_stable_session, retry_delay, ssh_failure,
};
pub(crate) use session::probe;
pub use session::run;
#[cfg(test)]
use session::run_with_backoff;

#[cfg(test)]
mod tests;
