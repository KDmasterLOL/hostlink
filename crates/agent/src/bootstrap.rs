//! Fresh-install package verification and enrollment finalization.

use crate::agent_files::{
    hash_file, is_reparse_point, validate_path_has_no_reparse_components, validate_user_owned_root,
};
#[cfg(unix)]
use crate::package::EXECUTABLE_BASE;
use crate::package::{
    ARCHIVE_DIGEST, BootstrapReceipt, MAX_ARCHIVE_BYTES, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES,
    PACKAGE_MANIFEST, PackageManifest, executable_name, invalid, invalid_owned, package_files,
    read_installed, supported_targets, target_matches_runtime, validate_contents,
    validate_installed,
};
use hex::FromHex;
use private_fs::PrivateDir;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub fn verify_fresh_package(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    output: &Path,
) -> io::Result<()> {
    let archive_sha256 = <[u8; 32]>::from_hex(archive_sha256)
        .map_err(|_| invalid("Agent archive SHA-256 must contain 32 hexadecimal bytes"))?;
    // The receipt and archive.sha256 persist the canonical lowercase representation.
    let archive_sha256 = hex::encode(archive_sha256);
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
        validate_and_stage_archive(&canonical_archive, &archive_sha256, target, version, parent)?;
    let staged_package = staged
        .path
        .join("extracted")
        .join(format!("hostlink-agent-{target}"));
    let running = std::env::current_exe()?;
    let expected_executable = manifest
        .files
        .get(executable_name(target))
        .ok_or_else(|| invalid("Agent executable identity is missing from manifest"))?;
    if hash_file(&running, MAX_ENTRY_BYTES)? != expected_executable.sha256 {
        return Err(invalid(
            "verifier sidecar does not match the package Agent executable",
        ));
    }
    let package_dir = PrivateDir::open(&staged_package).map_err(io::Error::other)?;
    {
        let mut receipt_file = package_dir
            .create("bootstrap-receipt.json")
            .map_err(io::Error::other)?;
        serde_json::to_writer_pretty(
            &mut receipt_file,
            &serde_json::json!({
                "format": 2,
                "component": manifest.component,
                "target": manifest.target,
                "version": manifest.version,
                "archive_sha256": archive_sha256,
                "sidecar_sha256": expected_executable.sha256,
                "files": manifest.files,
            }),
        )?;
        receipt_file.sync_all().map_err(io::Error::other)?;
    } // Close file handles before renaming on Windows.
    drop(package_dir);
    // Windows std::fs::File::open cannot open a directory for sync_all.
    // The member files and receipt have already been individually flushed;
    // the directory durability barrier is available on Unix only.
    #[cfg(not(windows))]
    PrivateDir::open(&staged_package)
        .and_then(|dir| dir.sync_all())
        .map_err(io::Error::other)?;
    fs::rename(&staged_package, output)?;
    #[cfg(not(windows))]
    PrivateDir::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(io::Error::other)?;
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
    let root_dir = PrivateDir::open(root).map_err(io::Error::other)?;
    drop(
        root_dir
            .open_file("enrollment.pending")
            .map_err(io::Error::other)?,
    );

    PrivateDir::open(root.join("state"))
        .and_then(|dir| dir.open_file("agent.json"))
        .and_then(|file| file.verify())
        .map_err(io::Error::other)?;

    let (installed, installed_archive_sha256) = read_installed(root)?;
    // read_installed already validates format, runtime target, inventory and hashes.
    if installed.version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(
            "fresh installed package target or version does not match this Agent",
        ));
    }
    let receipt_file = root_dir
        .open_file("bootstrap-receipt.json")
        .map_err(io::Error::other)?;
    let mut receipt_bytes = Vec::new();
    receipt_file
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut receipt_bytes)?;
    if receipt_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("bootstrap receipt exceeds its size limit"));
    }
    let receipt: BootstrapReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| invalid_owned(format!("invalid bootstrap receipt: {error}")))?;
    if receipt.format != 2
        || receipt.component != "agent"
        || receipt.target != installed.target
        || receipt.version != installed.version
        || <[u8; 32]>::from_hex(&receipt.archive_sha256)
            .map_err(|_| invalid("bootstrap receipt archive SHA-256 is invalid"))?
            != installed_archive_sha256
        || receipt.files != installed.files
    {
        return Err(invalid(
            "bootstrap receipt does not match installed package metadata",
        ));
    }
    let executable_identity = receipt
        .files
        .get(executable_name(&installed.target))
        .ok_or_else(|| invalid("bootstrap receipt omits the Agent executable"))?;
    if receipt.sidecar_sha256 != executable_identity.sha256 {
        return Err(invalid(
            "bootstrap receipt sidecar identity does not match the package",
        ));
    }
    fs::remove_file(&pending)?;
    #[cfg(not(windows))]
    PrivateDir::open(root)
        .and_then(|dir| dir.sync_all())
        .map_err(io::Error::other)?;
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
    PrivateDir::open(path).map(|_| ()).map_err(io::Error::other)
}

// Fresh-only, private-at-creation staging. Never used by self_update publication.
fn validate_and_stage_archive(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    staging_parent: &Path,
) -> io::Result<(PackageManifest, PrivateTempDir)> {
    let name = format!(".agent-package-{}", uuid::Uuid::new_v4());
    // Private native creation is required even on Windows; tempfile inherits ACLs.
    let stage_dir = PrivateDir::open(staging_parent)
        .and_then(|dir| dir.create_dir(&name))
        .map_err(io::Error::other)?;
    let stage = PrivateTempDir {
        path: staging_parent.join(name),
    };
    let staged_archive = stage.path.join("package.zip");
    let mut source = File::open(archive_path)?;
    let source_size = source.metadata()?.len();
    if source_size == 0 || source_size > MAX_ARCHIVE_BYTES {
        return Err(invalid(
            "Agent package archive exceeds its compressed size limit",
        ));
    }
    let mut archive_copy = stage_dir.create("package.zip").map_err(io::Error::other)?;
    // Enforce the bound before writing a byte beyond it, even if the source
    // grows after its initial metadata check.
    let copied = io::copy(
        &mut (&mut source).take(MAX_ARCHIVE_BYTES),
        &mut archive_copy,
    )?;
    if copied == 0 {
        return Err(invalid("Agent package archive is empty"));
    }
    if copied == MAX_ARCHIVE_BYTES && source.read(&mut [0_u8; 1])? != 0 {
        return Err(invalid(
            "Agent package archive exceeds its compressed size limit",
        ));
    }
    archive_copy.sync_all().map_err(io::Error::other)?;
    drop(archive_copy);
    if hash_file(&staged_archive, MAX_ARCHIVE_BYTES)? != archive_sha256 {
        return Err(invalid("selected Agent archive SHA-256 does not match"));
    }
    let (manifest, bytes) = validate_contents(&staged_archive, target, version)?;
    let expected_order = package_files(target)
        .into_iter()
        .chain(std::iter::once(PACKAGE_MANIFEST.to_owned()))
        .collect::<Vec<_>>();

    // The ZIP reader validates member names, types and declared sizes before extraction.
    // After extraction, verify actual file hashes against the package manifest
    // before publishing the fresh installation.
    let extraction_root = stage.path.join("extracted");
    let extraction_dir = stage_dir
        .ensure_dir("extracted")
        .map_err(io::Error::other)?;
    let package_root = extraction_root.join(format!("hostlink-agent-{target}"));
    let package_dir = extraction_dir
        .ensure_dir(format!("hostlink-agent-{target}"))
        .map_err(io::Error::other)?;
    // self_update truncates these exact precreated files. It must not create Windows
    // files/directories with inherited ACLs and then repair them after exposure.
    for name in &expected_order {
        package_dir.create(name).map_err(io::Error::other)?;
    }
    self_update::Extract::from_source(&staged_archive)
        .archive(self_update::ArchiveKind::Zip)
        .extract_into(&extraction_root)
        .map_err(|error| invalid_owned(format!("Agent ZIP extraction failed: {error}")))?;
    for name in &expected_order {
        set_staged_file_permissions(&package_root.join(name), name)?;
    }
    {
        let mut digest_file = package_dir
            .create(ARCHIVE_DIGEST)
            .map_err(io::Error::other)?;
        digest_file.write_all(archive_sha256.as_bytes())?;
        digest_file.sync_all().map_err(io::Error::other)?;
    }
    // Use the installed-package owner for the same exact inventory and file identities.
    validate_installed(&package_root, &manifest, target)?;
    let extracted_manifest = fs::read(package_root.join(PACKAGE_MANIFEST))?;
    if extracted_manifest != bytes {
        return Err(invalid(
            "Agent ZIP extracted manifest differs from its verified bytes",
        ));
    }
    Ok((manifest, stage))
}

struct PrivateTempDir {
    path: PathBuf,
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        // Refuse cleanup if the owned staging root has become a link or lost privacy.
        let cleanup = PrivateDir::open(&self.path)
            .map_err(io::Error::other)
            .and_then(|dir| {
                drop(dir);
                std::fs::remove_dir_all(&self.path)
            });
        if let Err(error) = cleanup {
            eprintln!(
                "private Agent staging cleanup failed at {}: {error}",
                self.path.display()
            );
        }
    }
}

pub(super) fn set_staged_file_permissions(path: &Path, relative: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Only freshly extracted files in our private staging tree are adopted here.
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        private_fs::harden(&file).map_err(io::Error::other)?;
        if relative == EXECUTABLE_BASE {
            // private-fs requires regular files to be exactly 0600. The executable alone
            // needs 0700 and is subsequently verified by the executable-specific contract.
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = relative;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("staged file has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("staged file has no name"))?;
        PrivateDir::open(parent)
            .and_then(|dir| dir.open_file(name))
            .and_then(|file| file.verify())
            .map_err(io::Error::other)?;
    }
    Ok(())
}
