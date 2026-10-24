//! Controller-side client for the HostLink Hub enrollment and discovery service.
//!
//! Configuration/secret persistence, redacted wire models, and async authenticated HTTP
//! operations have separate owners while the historical flat public API remains unchanged.

use crate::{AppResult, HubHttpsUrl, RemoteCarrier, RemoteServer, config_path, io_error};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod client;
mod config;
mod model;
mod routing;

pub use client::HubClient;
pub use config::{ControllerGateway, HubControllerConfig, ManagedTargetEffect, hub_config_path};
pub use model::{HubAgent, HubInvite};
pub use routing::{hub_runtime_server, resolve_remote_server};

use model::{AgentsResponse, ControlCredentialResponse, HubInfoResponse, InviteRequest};

#[cfg(test)]
mod tests;
