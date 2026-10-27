//! Source-pinned invitation installer selection and copyable bootstrap rendering.

mod render;
mod validate;
mod verify;

pub use render::{invitation_is_unexpired, render_command};
pub use validate::{ArtifactSelection, BootstrapError, Target, VerifiedInstaller};
pub use verify::{parse_artifact_url, verify_installer};

#[cfg(test)]
use reqwest::Url;
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
use validate::{https_url, semver, validate_installer_contract};
#[cfg(test)]
use verify::{fetch_bytes, validate_installer_bytes};

#[cfg(test)]
mod tests;
