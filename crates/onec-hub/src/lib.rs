//! Shared value contracts for the onec-hub server and controller clients.
//!
//! Server persistence, enrollment, authorization and HTTP handlers stay private to the
//! `onec-hub` binary. This library exposes only the small contracts that both the server and
//! controller-side access product must interpret identically.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod gateway;
mod hub_url;
pub use gateway::GatewayEndpoint;
pub use hub_url::{HubHttpsUrl, HubUrlError};
