//! Enrollment and agent-revocation workflows.
//!
//! SSH lookup, enrollment mutation, revocation, and boundary validation are
//! separate owners behind this internal façade.

mod credential;
mod lookup;
mod remove;
mod validation;
mod workflow;

pub(super) use credential::get_control_credential;
#[cfg(test)]
pub(super) use lookup::lookup_authorized_key;
pub(super) use lookup::ssh_authorized_key_lookup;
pub(super) use remove::remove_agent_request;
pub(super) use validation::{
    normalize_public_key, validate_enrollment, validate_identifier, validate_machine_id,
};
pub(super) use workflow::enroll_request;
#[cfg(test)]
pub(crate) use workflow::write_enrollment_commit_error;
