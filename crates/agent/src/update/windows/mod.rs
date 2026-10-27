//! Windows stopped-runtime publication, recovery, and filesystem safeguards.

mod fs;
mod publication;
mod recovery;
#[cfg(test)]
mod tests;

pub(crate) use fs::reject_running_agent;
pub(super) use fs::{set_windows_private_acl, validate_windows_private_acl};
pub(super) use publication::{
    ensure_windows_offline_caller, ensure_windows_separate_updater, publish_windows,
};
pub(crate) use recovery::ensure_no_pending_windows_handoff;
pub(super) use recovery::recover_windows_handoff;
