//! Managed reverse SSH and optional target-side SSH server supervision.
//!
//! The outbound client is in-process russh. Target-side external sshd remains a separately owned
//! compatibility boundary until the parent embedded-server migration is promoted.

use super::*;
use std::time::Duration;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

mod child;
mod client;
mod embedded_server;
mod forward;
mod proxy;
mod spawn;
mod sshd_host;
mod supervisor;

pub use child::TunnelChild;
pub(crate) use sshd_host::run as run_sshd_host;
#[cfg(windows)]
pub(crate) use supervisor::run_with_tunnel_until;
pub use supervisor::{probe_tunnel, run_with_tunnel};

use client::ReverseTunnel;
use embedded_server::EmbeddedSshServerHandle;
use spawn::{spawn_ssh_server, wait_for_ssh_server};
