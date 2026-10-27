#![cfg(unix)]

//! Opt-in process-level acceptance for the real Hub, HTTPS proxy, OpenSSH gateway,
//! enrollment Agent, and pinned russh Controller path. Run via the fixture script.

use hostlink::{
    connect::HostConnection,
    forward,
    hub::{HubClient, HubConfig},
    run::{JobSpec, JobState, JobStream, Output, Start, Status},
};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "e2e_steps/bootstrap.rs"]
mod bootstrap;
#[path = "e2e_steps/cleanup.rs"]
mod cleanup;
#[path = "e2e_steps/cli.rs"]
mod cli;
#[path = "e2e_steps/enrollment.rs"]
mod enrollment;
#[path = "e2e_steps/fixture.rs"]
mod fixture;
#[path = "e2e_steps/gateway.rs"]
mod gateway;
#[path = "e2e_steps/gateway_jobs.rs"]
mod gateway_jobs;
#[path = "e2e_steps/https.rs"]
mod https;
#[path = "e2e_steps/hub.rs"]
mod hub;
#[path = "e2e_steps/installer.rs"]
mod installer;
#[path = "e2e_steps/installer_enrollment.rs"]
mod installer_enrollment;
#[path = "e2e_steps/revocation.rs"]
mod revocation;
#[path = "e2e_steps/run.rs"]
mod run;
#[path = "e2e_steps/ssh.rs"]
mod ssh;

use bootstrap::*;
use fixture::*;
use ssh::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires openssh-server, Caddy, OpenSSL, and the fixture script"]
async fn actual_https_hub_enrollment_openssh_projection_and_managed_russh_flow() {
    run::run_managed_https_gateway_fixture(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires openssh-server, Caddy, OpenSSL, packaged artifacts, and the fixture script"]
async fn actual_cli_invite_https_installer_enrollment_and_managed_russh_flow() {
    run::run_managed_https_gateway_fixture(true).await;
}
