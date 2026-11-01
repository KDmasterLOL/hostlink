//! HTTPS management client for the authoritative HostLink Hub v2 registry.

mod client;
mod config;
mod routes;

pub use client::HubClient;
pub use config::{HubClientError, HubConfig};
pub use hostlink_hub::RevokeReceipt;
pub use routes::{host_spec_from, host_spec_from_approved_routes};

#[cfg(test)]
use config::{MAX_BODY_BYTES, parse_origin, select_host};
#[cfg(test)]
use hostlink_hub::{GatewayEndpoint, RegisteredHost};
#[cfg(test)]
use reqwest::{Method, Url};
#[cfg(test)]
use routes::{select_primary_gateway, validate_gateway_list};
#[cfg(test)]
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(test)]
mod tests;
