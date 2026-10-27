//! Explicit, one-shot enrollment of a fresh user-owned Agent root.

use crate::{AgentConfig, ReverseGateway, durable};
use hostlink_hub::{EnrollRequest, EnrollResponse, GatewayEndpoint, MachineId};
use rand::{RngExt, rng};
use reqwest::{Client, Url, redirect::Policy};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

const MAX_TOKEN_BYTES: u64 = 4096;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ENROLLMENT_PATH: &str = "/v2/enroll";
// This range avoids the commonly used dynamic client-port ranges on Linux and Windows,
// but operating-system port-range configuration is not universal.
const AGENT_LISTENER_PORTS: std::ops::RangeInclusive<u16> = 20_000..=29_999;
const LISTENER_PORT_ATTEMPTS: usize = 32;

mod flow;
mod local_state;
mod platform;
mod validation;

#[cfg(test)]
use flow::*;
pub use flow::{
    EnrollmentIdentity, EnrollmentOptions, EnrollmentResult, prepare_enrollment,
    prepare_enrollment_with_ca,
};
use local_state::*;
use platform::*;
use validation::*;

#[cfg(test)]
mod tests;
