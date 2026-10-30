//! Windows stopped-runtime publication, recovery, and filesystem safeguards.

mod fs;
mod publication;
mod recovery;
#[cfg(test)]
mod tests;

pub(super) use fs::{
    create_private_directory, set_windows_private_acl, validate_windows_private_acl,
};
pub(super) use publication::{ensure_windows_offline_caller, publish_windows};
pub(super) use recovery::recover_windows_handoff;
