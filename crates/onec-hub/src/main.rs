//! onec-hub process bootstrap.
//!
//! The binary root wires configuration/state into the HTTP server. Audit, persisted
//! state, enrollment, authorization, port allocation, and authorized-keys mutation
//! are owned by dedicated modules.

use chrono::Utc;
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

mod http;
mod security;
use http::{ApiResponse, internal_error, invalid, json, json_error, parse_json_body, text};
use security::{
    derive_control_secret, random_control_credential_nonce, random_secret, token_digest,
    validate_control_credential_nonce,
};

pub(crate) use onec_hub::HubHttpsUrl;

const CONFIG_VERSION: u32 = 1;
const LEGACY_STATE_VERSION: u32 = 1;
const STATE_VERSION: u32 = 2;
const HUB_AUDIT_SCHEMA_VERSION: u32 = 1;

mod allocation;
mod audit;
mod authorized_keys;
mod cli;
mod config;
mod display_name;
mod enrollment;
mod model;
mod operator_auth;
mod server;
mod ssh_material;
mod state;

use allocation::*;
use audit::*;
use authorized_keys::*;
use cli::*;
use config::*;
use enrollment::*;
use model::*;
use operator_auth::*;
use server::*;
use state::*;

fn main() {
    if let Err(error) = run() {
        eprintln!("onec-hub: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let cli = Cli::parse();
    let config_path = match &cli.command {
        Command::Check { config } | Command::Serve { config } => config,
    };
    let config = HubConfig::load(config_path)?;
    let operator_token = config.operator_token()?;
    let agent_secret_key = config.agent_secret_key()?;
    let ssh_lookup_token = config.ssh_lookup_token()?;

    match cli.command {
        Command::Check { .. } => {
            let state = HubState::load(&config.state_file)?;
            println!(
                "{}",
                serde_json::json!({
                    "listen": config.listen,
                    "public_url": config.public_url,
                    "gateways": config.gateways,
                    "agents": state.agents.len(),
                    "state_file": config.state_file,
                    "authorized_keys": config.authorized_keys,
                    "remote_port_range": [config.port_from, config.port_to],
                    "reserved_ports": config.reserved_ports,
                    "probe_gateway_ports_locally": config.probe_gateway_ports_locally,
                })
            );
            Ok(())
        }
        Command::Serve { .. } => {
            let app = App {
                config,
                operator_token,
                agent_secret_key,
                ssh_lookup_token,
                state_writer: Mutex::new(()),
            };
            run_server(app)
        }
    }
}

fn run_server(app: App) -> io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(app))
}

#[cfg(test)]
mod tests;
