//! Exact, local, Agent-only package updates.
//!
//! Updates are serialized with an OS file lock, staged under the user-owned install root,
//! and published only after the selected archive, target, version, and file manifest agree.
//! Windows publication is limited to a separately invoked, current-user-private updater. A
//! registered Agent is updated through its authenticated maintenance and health-check handoff.

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
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{ensure_no_pending_windows_handoff, reject_running_agent};

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
    DeferredActiveJobs {
        job_ids: Vec<String>,
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
/// The durable-job store beneath `install_root` is read under the same update lock. Any returned
/// job ID defers the update; corrupt or unreadable job state is propagated as an error by
/// `jobs::active_ids`.
pub fn apply(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    validate_request(request)?;
    private_fs::validate_user_owned_root(&request.install_root)?;
    let archive_path =
        archive::validate_archive_path(&request.install_root, &request.archive_file)?;
    let _update_lock = crate::jobs::acquire_update_lock(&request.install_root)?;

    let jobs_root = request.install_root.join("jobs");
    let active_ids = crate::jobs::active_ids(&jobs_root)?;
    if !active_ids.is_empty() {
        return Ok(AgentUpdateOutcome::DeferredActiveJobs {
            job_ids: active_ids,
        });
    }
    #[cfg(windows)]
    windows::ensure_windows_separate_updater(&request.install_root)?;
    #[cfg(windows)]
    let registered_service = crate::service::has_registration(&request.install_root)?;
    #[cfg(windows)]
    if registered_service {
        let pending_journal = crate::update_handoff::read_journal(
            &request.install_root.join(".updates/handoff.json"),
        )?;
        let pending = pending_journal.is_some();
        if crate::service::is_in_maintenance(&request.install_root)? {
            if !pending {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "service maintenance marker has no matching update journal; state preserved for manual recovery",
                ));
            }
            crate::service::recover_maintenance_stop(&request.install_root)?;
            windows::recover_windows_handoff(&request.install_root, true, false)?;
            crate::service::recover_maintenance_after_inventory(&request.install_root, |root| {
                let metadata = manifest::read_install_metadata(&root.join(INSTALL_METADATA))?;
                manifest::validate_installed(&root.join("bin"), &metadata, &metadata.target)
            })?;
        } else if pending {
            let journal = pending_journal.expect("pending journal was checked");
            match journal.phase {
                crate::update_handoff::UpdatePhase::Staged => {
                    crate::service::verify_registered_image(
                        &request.install_root,
                        &journal.identity.old_executable_sha256,
                    )?;
                    windows::recover_windows_handoff(&request.install_root, false, false)?;
                }
                crate::update_handoff::UpdatePhase::RolledBack => {
                    crate::service::recover_maintenance_after_inventory(
                        &request.install_root,
                        |root| {
                            let metadata =
                                manifest::read_install_metadata(&root.join(INSTALL_METADATA))?;
                            manifest::validate_installed(
                                &root.join("bin"),
                                &metadata,
                                &metadata.target,
                            )
                        },
                    )?;
                    crate::service::verify_registered_image(
                        &request.install_root,
                        &journal.identity.old_executable_sha256,
                    )?;
                    windows::recover_windows_handoff(&request.install_root, false, false)?;
                }
                crate::update_handoff::UpdatePhase::Restarted => {
                    if let Err(health_error) = crate::service::verify_registered_health(
                        &request.install_root,
                        &journal.identity.new_executable_sha256,
                    ) {
                        crate::service::begin_recovery_maintenance(
                            &request.install_root,
                            &journal.identity.old_executable_sha256,
                            &journal.identity.new_executable_sha256,
                        )?;
                        crate::service::recover_maintenance_stop(&request.install_root)?;
                        windows::recover_windows_handoff(&request.install_root, true, false)?;
                        crate::service::recover_maintenance_after_inventory(
                            &request.install_root,
                            |root| {
                                let metadata =
                                    manifest::read_install_metadata(&root.join(INSTALL_METADATA))?;
                                manifest::validate_installed(
                                    &root.join("bin"),
                                    &metadata,
                                    &metadata.target,
                                )
                            },
                        )?;
                        return Err(io::Error::other(format!(
                            "previous Agent candidate failed health readback ({health_error}); exact old inventory was restored and registered"
                        )));
                    }
                    windows::recover_windows_handoff(&request.install_root, false, true)?;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "interrupted Windows update has no consistent owner maintenance state; journal preserved",
                    ));
                }
            }
        }
    } else {
        windows::ensure_windows_offline_caller(&request.install_root)?;
        windows::recover_windows_handoff(&request.install_root, false, false)?;
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
        registered_service,
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
