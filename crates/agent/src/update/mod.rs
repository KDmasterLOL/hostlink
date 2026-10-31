//! Exact, local, Agent-only package updates.
//!
//! Updates are serialized with an OS file lock, staged under the user-owned install root,
//! and published only after the selected archive, target, version, and file manifest agree.
//! Windows publication is limited to a separately invoked, current-user-private updater. A
//! registered Agent must be stopped and its task removed before an offline update.

use crate::private_fs::PrivateFileExt;
use ::private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
#[cfg(not(windows))]
use manifest::InstallMetadata;
#[cfg(not(windows))]
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};

mod archive;
mod bootstrap;
#[cfg(not(windows))]
mod linux;
mod manifest;
mod private_fs;
mod staging;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

pub use bootstrap::{finalize_fresh_install, verify_fresh_package};

/// One exact, externally selected Agent package. `archive_file` must be beneath `install_root`.
#[derive(Clone, Debug)]
pub struct AgentUpdateRequest {
    pub install_root: PathBuf,
    pub archive_file: PathBuf,
    pub archive_sha256: String,
    pub target: String,
    pub version: String,
}

/// The updater's externally visible result.
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

#[cfg(not(windows))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::update) struct PublicationJournal {
    pub(in crate::update) format: u32,
    pub(in crate::update) backup: String,
    pub(in crate::update) old_metadata: InstallMetadata,
}

/// Validate and apply one exact Agent archive.
///
/// The updater does not inspect Apalis internals. On Linux it requires the
/// Agent process to have released its lifetime lock before publication;
/// Windows requires removal of the logon task and a separate offline updater.
pub fn apply(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    validate_request(request)?;
    private_fs::validate_user_owned_root(&request.install_root)?;
    let archive_path =
        archive::validate_archive_path(&request.install_root, &request.archive_file)?;
    let update_file = PrivateDir::open(std::path::absolute(&request.install_root)?)
        .map_err(io::Error::other)?
        .open_file_with(
            "update.lock",
            OpenOptions {
                access: FileAccess::ReadWrite,
                creation: FileCreation::OpenOrCreate,
                ..OpenOptions::default()
            },
        )
        .map_err(io::Error::other)?
        .try_clone_std()?;
    #[cfg(not(windows))]
    update_file.lock()?;
    #[cfg(windows)]
    update_file.try_lock().map_err(io::Error::other)?;
    let _stopped_agent = {
        // This lock describes the Agent process, not any SQLite state.
        let file = PrivateDir::open(std::path::absolute(request.install_root.join("jobs"))?)
            .map_err(io::Error::other)?
            .open_file_with(
                "runner.lock",
                OpenOptions {
                    access: FileAccess::ReadWrite,
                    creation: FileCreation::OpenOrCreate,
                    ..OpenOptions::default()
                },
            )
            .map_err(io::Error::other)?
            .try_clone_std()?;
        file.try_lock().map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("stop the running Agent before updating it: {error}"),
            )
        })?;
        file
    };
    #[cfg(windows)]
    {
        windows::ensure_windows_offline_caller(&request.install_root)?;
        windows::recover_windows_handoff(&request.install_root)?;
    }
    #[cfg(not(windows))]
    linux::recover_interrupted_publication(&request.install_root)?;

    let (manifest, staged_files) = archive::validate_and_stage_archive(
        &archive_path,
        &request.archive_sha256,
        &request.target,
        &request.version,
        &request.install_root,
    )?;
    let bin_root = request.install_root.join("bin");
    let metadata_path = request.install_root.join(INSTALL_METADATA);
    let old_metadata = manifest::read_install_metadata(&metadata_path)?;
    manifest::validate_installed(&bin_root, &old_metadata, &request.target)?;

    if old_metadata.installed_package_sha256 == request.archive_sha256 {
        if old_metadata.installed_version != request.version {
            return Err(invalid(
                "installed version conflicts with the selected archive SHA-256",
            ));
        }
        drop(staged_files);
        return Ok(AgentUpdateOutcome::AlreadyCurrent {
            version: request.version.clone(),
            archive_sha256: request.archive_sha256.clone(),
        });
    }

    #[cfg(windows)]
    windows::publish_windows(
        &request.install_root,
        &metadata_path,
        request,
        manifest,
        old_metadata,
        staged_files,
    )?;

    #[cfg(windows)]
    {
        Ok(AgentUpdateOutcome::Installed {
            version: request.version.clone(),
            archive_sha256: request.archive_sha256.clone(),
        })
    }

    #[cfg(not(windows))]
    {
        linux::publish_linux(
            &request.install_root,
            &bin_root,
            &metadata_path,
            request,
            manifest,
            old_metadata,
            staged_files,
        )?;
        Ok(AgentUpdateOutcome::Installed {
            version: request.version.clone(),
            archive_sha256: request.archive_sha256.clone(),
        })
    }
}

pub(super) fn validate_request(request: &AgentUpdateRequest) -> io::Result<()> {
    if request.install_root.as_os_str().is_empty() || !request.install_root.is_absolute() {
        return Err(invalid("Agent install root must be an absolute path"));
    }
    validate_sha256(&request.archive_sha256)?;
    semver::Version::parse(&request.version)
        .map_err(|_| invalid("Agent package version must be exact semantic version"))?;
    if !supported_targets().contains(&request.target.as_str()) {
        return Err(invalid("unsupported Agent target triple"));
    }
    if !target_matches_runtime(&request.target) {
        return Err(invalid("Agent package target does not match this runtime"));
    }
    Ok(())
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
