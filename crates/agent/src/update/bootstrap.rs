//! Fresh-install package verification and enrollment finalization.

use super::{
    INSTALL_METADATA, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, PACKAGE_MANIFEST, invalid,
    invalid_owned, supported_targets, target_matches_runtime, validate_sha256,
};
use crate::update::archive::validate_and_stage_archive;
use crate::update::manifest::{
    BootstrapReceipt, InstallMetadata, package_files, read_install_metadata, validate_installed,
};
use crate::update::private_fs::{
    hash_file, is_reparse_point, open_private_file, set_staged_file_permissions,
    validate_path_has_no_reparse_components, validate_user_owned_root,
};
#[cfg(not(windows))]
use crate::update::private_fs::{sync_directory, validate_private_directory};
#[cfg(windows)]
use crate::update::windows::validate_windows_private_acl;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub fn verify_fresh_package(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    output: &Path,
) -> io::Result<()> {
    validate_sha256(archive_sha256)?;
    semver::Version::parse(version)
        .map_err(|_| invalid("Agent package version must be exact semantic version"))?;
    if version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(
            "verifier sidecar version does not match selected package version",
        ));
    }
    if !supported_targets().contains(&target) || !target_matches_runtime(target) {
        return Err(invalid("Agent package target does not match this runtime"));
    }
    let metadata = fs::symlink_metadata(archive_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid("Agent archive is not a regular file"));
    }
    validate_path_has_no_reparse_components(archive_path)?;
    let parent = output
        .parent()
        .ok_or_else(|| invalid("package output must have a parent directory"))?;
    validate_fresh_output_parent(parent)?;
    if output.exists() || fs::symlink_metadata(output).is_ok() {
        return Err(invalid("package output already exists"));
    }
    let canonical_archive = fs::canonicalize(archive_path)?;
    let (manifest, staged) =
        validate_and_stage_archive(&canonical_archive, archive_sha256, target, version, parent)?;
    let staged_package = staged
        .path()
        .join("extracted")
        .join(format!("hostlink-agent-{target}"));
    let executable = package_files(target)
        .into_iter()
        .find(|name| name == "hostlink-agent" || name == "hostlink-agent.exe")
        .ok_or_else(|| invalid("Agent executable is missing from package contract"))?;
    let running = std::env::current_exe()?;
    let expected_executable = manifest
        .files
        .get(&executable)
        .ok_or_else(|| invalid("Agent executable identity is missing from manifest"))?;
    if hash_file(&running, MAX_ENTRY_BYTES)? != expected_executable.sha256 {
        return Err(invalid(
            "verifier sidecar does not match the package Agent executable",
        ));
    }
    let install_metadata = InstallMetadata {
        format: 1,
        target: target.to_owned(),
        installed_version: version.to_owned(),
        installed_package_sha256: archive_sha256.to_owned(),
        installed_files: manifest.files.clone(),
    };
    let metadata_path = staged_package.join(INSTALL_METADATA);
    let mut metadata_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&metadata_path)?;
    metadata_file
        .write_all(&serde_json::to_vec_pretty(&install_metadata).map_err(io::Error::other)?)?;
    metadata_file.sync_all()?;
    set_staged_file_permissions(&metadata_path, INSTALL_METADATA)?;
    let receipt_path = staged_package.join("bootstrap-receipt.json");
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)?;
    receipt_file.write_all(
        &serde_json::to_vec_pretty(&serde_json::json!({
            "format": 1,
            "component": manifest.component,
            "target": manifest.target,
            "version": manifest.version,
            "archive_sha256": archive_sha256,
            "sidecar_sha256": expected_executable.sha256,
            "files": manifest.files,
        }))
        .map_err(io::Error::other)?,
    )?;
    receipt_file.sync_all()?;
    set_staged_file_permissions(&receipt_path, "bootstrap-receipt.json")?;
    fs::remove_file(staged_package.join(PACKAGE_MANIFEST))?;
    // Windows refuses renaming a directory containing still-open file handles
    // (ERROR_ACCESS_DENIED), even after each file's sync_all has succeeded.
    // Publish only after closing both verified metadata and receipt files.
    drop(receipt_file);
    drop(metadata_file);
    // Windows std::fs::File::open cannot open a directory for sync_all.
    // The member files and receipt have already been individually flushed;
    // the directory durability barrier is available on Unix only.
    #[cfg(not(windows))]
    sync_directory(&staged_package)?;
    fs::rename(&staged_package, output)?;
    #[cfg(not(windows))]
    sync_directory(parent)?;
    println!(
        "Verified Agent package: target={target} version={version} archive_sha256={archive_sha256}"
    );
    Ok(())
}

/// Complete a fresh bootstrap only after the ZIP's extracted binaries and receipt are installed.
///
/// # Errors
///
/// Returns an error unless the install root, enrollment state, installed package, source receipt,
/// and pending marker all validate. On error the pending marker remains for reconciliation.
pub fn finalize_fresh_install(root: &Path) -> io::Result<()> {
    validate_user_owned_root(root)?;
    let pending = root.join("enrollment.pending");
    let pending_file = open_private_file(&pending, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(&pending, &pending_file.metadata()?)?;
    drop(pending_file);

    let state = root.join("state");
    let state_metadata = fs::symlink_metadata(&state)?;
    if !state_metadata.is_dir()
        || state_metadata.file_type().is_symlink()
        || is_reparse_point(&state_metadata)
    {
        return Err(invalid("fresh Agent state directory is missing or unsafe"));
    }
    #[cfg(not(windows))]
    validate_private_directory(&state, &state_metadata)?;
    #[cfg(windows)]
    validate_windows_private_acl(&state, &state_metadata)?;
    let config = state.join("agent.json");
    let config_metadata = fs::symlink_metadata(&config)?;
    if !config_metadata.is_file()
        || config_metadata.file_type().is_symlink()
        || is_reparse_point(&config_metadata)
    {
        return Err(invalid("fresh Agent configuration is missing or unsafe"));
    }
    #[cfg(windows)]
    validate_windows_private_acl(&config, &config_metadata)?;

    let metadata_path = root.join(INSTALL_METADATA);
    let installed = read_install_metadata(&metadata_path)?;
    if !supported_targets().contains(&installed.target.as_str())
        || !target_matches_runtime(&installed.target)
        || installed.installed_version != env!("CARGO_PKG_VERSION")
    {
        return Err(invalid(
            "fresh installed package target or version does not match this Agent",
        ));
    }
    validate_installed(&root.join("bin"), &installed, &installed.target)?;
    let receipt_path = root.join("bootstrap-receipt.json");
    let receipt_file = open_private_file(&receipt_path, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(&receipt_path, &receipt_file.metadata()?)?;
    let mut receipt_bytes = Vec::new();
    receipt_file
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut receipt_bytes)?;
    if receipt_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("bootstrap receipt exceeds its size limit"));
    }
    let receipt: BootstrapReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| invalid_owned(format!("invalid bootstrap receipt: {error}")))?;
    let executable = package_files(&installed.target)
        .into_iter()
        .find(|name| name == "hostlink-agent" || name == "hostlink-agent.exe")
        .ok_or_else(|| invalid("Agent executable is missing from package contract"))?;
    if receipt.format != 1
        || receipt.component != "agent"
        || receipt.target != installed.target
        || receipt.version != installed.installed_version
        || receipt.archive_sha256 != installed.installed_package_sha256
        || receipt.files != installed.installed_files
    {
        return Err(invalid(
            "bootstrap receipt does not match installed package metadata",
        ));
    }
    let executable_identity = receipt
        .files
        .get(&executable)
        .ok_or_else(|| invalid("bootstrap receipt omits the Agent executable"))?;
    if receipt.sidecar_sha256 != executable_identity.sha256 {
        return Err(invalid(
            "bootstrap receipt sidecar identity does not match the package",
        ));
    }
    fs::remove_file(&pending)?;
    #[cfg(not(windows))]
    sync_directory(root)?;
    Ok(())
}

fn validate_fresh_output_parent(path: &Path) -> io::Result<()> {
    validate_path_has_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid(
            "package output parent is not a real private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and reads only the current process identity.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                "package output parent is not private and user-owned",
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_private_acl(path, &metadata)?;
    Ok(())
}
