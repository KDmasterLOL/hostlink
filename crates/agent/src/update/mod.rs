//! One exact HTTPS Agent update, published by self_update's bundle transaction.
//! Persistent state is private; downloaded archives and bin bundles are nonsecret.
//! Ordinary failures use upstream in-process rollback, not crash/power-loss recovery.

use std::{io, path::PathBuf};

mod admission;
mod archive;
mod artifact;
mod bootstrap;
mod installed;
mod manifest;
mod private_fs;
mod publication;
mod staging;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use admission::ensure_no_legacy_update;
pub use artifact::Artifact;
pub use bootstrap::{finalize_fresh_install, verify_fresh_package};
pub(crate) use installed::verify_executable;

#[derive(Clone, Debug)]
pub struct AgentUpdateRequest {
    pub install_root: PathBuf,
    pub artifact: Artifact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentUpdateOutcome {
    AlreadyCurrent {
        version: String,
        archive_sha256: String,
    },
    Installed {
        version: String,
        archive_sha256: String,
    },
}

pub(super) const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub(super) const PACKAGE_MANIFEST: &str = "manifest.json";
pub(super) const INSTALL_METADATA: &str = "install.json";
pub(super) const EXECUTABLE_BASE: &str = "hostlink-agent";

/// Apply one independently pinned URL to a fully stopped Agent.
/// No Agent/service restart is performed. A kill between upstream renames may leave bin absent.
pub fn apply(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    let _locks = admission::acquire(&request.install_root)?;
    let old = installed::read(&request.install_root)?;
    let selected = &request.artifact;
    if old.target != selected.target {
        return Err(invalid(
            "selected Agent target differs from installed target",
        ));
    }
    if old.installed_package_sha256 == selected.sha256 {
        if old.installed_version != selected.version {
            return Err(invalid(
                "installed version conflicts with the selected archive SHA-256",
            ));
        }
        if old.format == 2 {
            return Ok(AgentUpdateOutcome::AlreadyCurrent {
                version: selected.version.clone(),
                archive_sha256: selected.sha256.clone(),
            });
        }
        // A legacy format-1 installation is republished once to migrate metadata with bin.
    }
    publication::update(request, &old)?;
    Ok(AgentUpdateOutcome::Installed {
        version: selected.version.clone(),
        archive_sha256: selected.sha256.clone(),
    })
}

pub(super) fn validate_sha256(digest: &str) -> io::Result<()> {
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "SHA-256 must contain 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub(super) fn supported_targets() -> &'static [&'static str] {
    &[
        "x86_64-pc-windows-msvc",
        "x86_64-win7-windows-msvc",
        "i686-win7-windows-msvc",
        "x86_64-unknown-linux-gnu",
    ]
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn target_matches_runtime(target: &str) -> bool {
    target == "x86_64-unknown-linux-gnu"
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(super) fn target_matches_runtime(target: &str) -> bool {
    matches!(
        target,
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc"
    )
}

#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub(super) fn target_matches_runtime(target: &str) -> bool {
    target == "i686-win7-windows-msvc"
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86")
)))]
pub(super) fn target_matches_runtime(_target: &str) -> bool {
    false
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
