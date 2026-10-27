//! Windows stopped-runtime publication flow.

use super::super::super::manifest::{
    InstallMetadata, PackageManifest, read_install_metadata, validate_installed,
};
use super::super::super::private_fs::{
    hash_file, is_reparse_point, set_private_directory, validate_path_has_no_reparse_components,
};
use super::super::super::{
    AgentUpdateRequest, INSTALL_METADATA, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, invalid,
    invalid_owned,
};
use super::super::fs::{
    copy_private_synced, create_private_directory, reject_running_agent, same_windows_file,
    sha256_hex, validate_windows_private_acl, verify_windows_private_file, windows_file_identity,
    write_private_synced,
};
use super::{cleanup::cleanup_windows_transaction, rollback::rollback_windows};
use std::{fs, io, path::Path};

#[cfg(windows)]
pub(in crate::update) fn publish_windows(
    root: &Path,
    metadata_path: &Path,
    request: &AgentUpdateRequest,
    manifest: PackageManifest,
    old_metadata: InstallMetadata,
    staged: tempfile::TempDir,
    managed_service: bool,
) -> io::Result<()> {
    let bin_root = root.join("bin");
    let installed_executable = bin_root.join("hostlink-agent.exe");
    if managed_service {
        if same_windows_file(&std::env::current_exe()?, &installed_executable)? {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "managed update must be invoked by a separate updater executable",
            ));
        }
    } else {
        ensure_windows_offline_caller(root)?;
    }

    let updates = root.join(".updates");
    create_private_directory(&updates)?;
    let new_metadata = InstallMetadata {
        format: 1,
        target: request.target.clone(),
        installed_version: request.version.clone(),
        installed_package_sha256: request.archive_sha256.clone(),
        installed_files: manifest.files.clone(),
    };
    for (name, expected) in &manifest.files {
        if name == "hostlink-agent.exe" {
            continue;
        }
        let installed_path = bin_root.join(name);
        let staged_path = staged
            .path()
            .join("extracted")
            .join(format!("hostlink-agent-{}", request.target))
            .join(name);
        if hash_file(&installed_path, MAX_ENTRY_BYTES)? != expected.sha256
            || hash_file(&staged_path, MAX_ENTRY_BYTES)? != expected.sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "offline Windows update cannot change package support files in this transaction",
            ));
        }
    }
    let new_metadata_bytes = serde_json::to_vec_pretty(&new_metadata).map_err(io::Error::other)?;
    let old_metadata_bytes = fs::read(metadata_path)?;
    let old_executable_sha256 = hash_file(&installed_executable, MAX_ENTRY_BYTES)?;
    let new_executable_sha256 = manifest
        .files
        .get("hostlink-agent.exe")
        .ok_or_else(|| invalid("Windows Agent manifest has no executable identity"))?
        .sha256
        .clone();
    let identity = crate::update_handoff::UpdateIdentity {
        target: request.target.clone(),
        old_version: old_metadata.installed_version.clone(),
        old_archive_sha256: old_metadata.installed_package_sha256.clone(),
        old_executable_sha256,
        old_metadata_sha256: sha256_hex(&old_metadata_bytes),
        new_version: request.version.clone(),
        new_archive_sha256: request.archive_sha256.clone(),
        new_executable_sha256,
        new_metadata_sha256: sha256_hex(&new_metadata_bytes),
    };
    let journal = crate::update_handoff::UpdateJournal::new(identity)?;
    let transaction = journal.transaction_id();
    let transaction_dir = updates.join(format!("transaction-{transaction}"));
    fs::create_dir(&transaction_dir)?;
    set_private_directory(&transaction_dir)?;

    let staged_executable = transaction_dir.join("staged-agent.exe");
    let staged_metadata = transaction_dir.join("staged-install.json");
    let backup_executable = transaction_dir.join("backup-agent.exe");
    let backup_metadata = transaction_dir.join("backup-install.json");
    let journal_path = updates.join("handoff.json");
    let archive_executable = staged
        .path()
        .join("extracted")
        .join(format!("hostlink-agent-{}", request.target))
        .join("hostlink-agent.exe");

    let prepare = (|| {
        copy_private_synced(&archive_executable, &staged_executable)?;
        write_private_synced(&staged_metadata, &new_metadata_bytes)?;
        copy_private_synced(&installed_executable, &backup_executable)?;
        copy_private_synced(metadata_path, &backup_metadata)?;
        if hash_file(&staged_executable, MAX_ENTRY_BYTES)? != journal.identity.new_executable_sha256
            || hash_file(&staged_metadata, MAX_MANIFEST_BYTES)?
                != journal.identity.new_metadata_sha256
            || hash_file(&backup_executable, MAX_ENTRY_BYTES)?
                != journal.identity.old_executable_sha256
            || hash_file(&backup_metadata, MAX_MANIFEST_BYTES)?
                != journal.identity.old_metadata_sha256
        {
            return Err(invalid("Windows updater staged or backup digest mismatch"));
        }
        let files = crate::update_handoff::TransactionFiles {
            staged_executable: &staged_executable,
            staged_metadata: &staged_metadata,
            installed_executable: &installed_executable,
            installed_metadata: metadata_path,
            backup_executable: &backup_executable,
            backup_metadata: &backup_metadata,
        };
        let evidence = crate::update_handoff::inspect_files(&files, &journal.identity)?;
        if !evidence.staged_new_valid
            || !evidence.staged_new_metadata_valid
            || !evidence.installed_old_valid
            || !evidence.installed_old_metadata_valid
            || !evidence.backup_old_valid
            || !evidence.backup_old_metadata_valid
        {
            return Err(invalid(
                "Windows updater pre-publication evidence is incomplete",
            ));
        }
        crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
        Ok(())
    })();
    prepare?;

    // The durable journal and both verified backups precede service quiescence. A crash from
    // this point onward therefore leaves enough exact file evidence for conservative recovery.
    let maintenance = if managed_service {
        Some(crate::service::begin_maintenance(root)?)
    } else {
        None
    };

    let mut journal = journal;
    let publish = (|| {
        if maintenance.is_none() {
            crate::service::ensure_update_unregistered(root)?;
            ensure_windows_offline_caller(root)?;
        }
        journal.advance(crate::update_handoff::UpdatePhase::BackedUp)?;
        crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
        let mut moves = self_update::MoveAll::from_temp(&transaction_dir);
        moves
            .add(&staged_executable, &installed_executable)
            .add(&staged_metadata, metadata_path);
        moves
            .commit()
            .map_err(|error| invalid_owned(format!("Agent package publication failed: {error}")))?;
        verify_windows_private_file(&installed_executable)?;
        verify_windows_private_file(metadata_path)?;
        journal.advance(crate::update_handoff::UpdatePhase::Published)?;
        crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;

        let files = crate::update_handoff::TransactionFiles {
            staged_executable: &staged_executable,
            staged_metadata: &staged_metadata,
            installed_executable: &installed_executable,
            installed_metadata: metadata_path,
            backup_executable: &backup_executable,
            backup_metadata: &backup_metadata,
        };
        let evidence = crate::update_handoff::inspect_files(&files, &journal.identity)?;
        if !evidence.installed_new_valid
            || !evidence.installed_new_metadata_valid
            || !evidence.backup_old_valid
            || !evidence.backup_old_metadata_valid
        {
            return Err(invalid(
                "Windows installed inventory readback did not match the package",
            ));
        }
        let installed = read_install_metadata(metadata_path)?;
        if installed != new_metadata {
            return Err(invalid(
                "Windows installed metadata readback differs from the package",
            ));
        }
        validate_installed(&bin_root, &installed, &request.target)?;
        journal.advance(crate::update_handoff::UpdatePhase::Verified)?;
        crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
        if let Some(receipt) = maintenance.as_ref() {
            crate::service::update_maintenance_executable(
                receipt,
                &journal.identity.new_executable_sha256,
            )?;
            crate::service::start_maintenance_candidate(
                receipt,
                &journal.identity.new_executable_sha256,
            )?;
            journal.advance(crate::update_handoff::UpdatePhase::Restarted)?;
            crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
            crate::service::register_maintenance(receipt)?;
        }
        cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
    })();

    if let Err(error) = publish {
        if let Some(receipt) = maintenance.as_ref()
            && let Err(stop_error) = crate::service::stop_for_maintenance_rollback(receipt)
        {
            return Err(io::Error::other(format!(
                "Windows Agent update failed ({error}); candidate stop could not be proven ({stop_error}); journal and transaction at {} preserved",
                transaction_dir.display()
            )));
        }
        if let Err(rollback_error) = rollback_windows(
            &installed_executable,
            metadata_path,
            &backup_executable,
            &backup_metadata,
            &journal_path,
            &mut journal,
        ) {
            return Err(io::Error::other(format!(
                "Windows Agent publication failed ({error}); rollback failed ({rollback_error}); preserve transaction at {}",
                transaction_dir.display()
            )));
        }
        if let Some(receipt) = maintenance.as_ref()
            && let Err(restore_error) = crate::service::restore_maintenance(receipt, |root| {
                let old_metadata = read_install_metadata(&root.join(INSTALL_METADATA))?;
                validate_installed(&root.join("bin"), &old_metadata, &request.target)
            })
        {
            return Err(io::Error::other(format!(
                "Windows Agent update failed ({error}); old files are restored but owner registration recovery failed ({restore_error}); journal preserved at {}",
                journal_path.display()
            )));
        }
        if let Err(cleanup_error) =
            cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
        {
            return Err(io::Error::other(format!(
                "Windows Agent publication failed ({error}); rollback completed but transaction cleanup failed ({cleanup_error}); journal preserved at {}",
                journal_path.display()
            )));
        }
        return Err(error);
    }

    Ok(())
}

#[cfg(windows)]
pub(in crate::update) fn ensure_windows_offline_caller(root: &Path) -> io::Result<()> {
    ensure_windows_separate_updater(root)?;
    reject_running_agent(&root.join("bin").join("hostlink-agent.exe"))
}

#[cfg(windows)]
pub(in crate::update) fn ensure_windows_separate_updater(root: &Path) -> io::Result<()> {
    let updater = std::env::current_exe()?;
    let updater_metadata = fs::symlink_metadata(&updater)?;
    if !updater_metadata.is_file()
        || updater_metadata.file_type().is_symlink()
        || is_reparse_point(&updater_metadata)
    {
        return Err(invalid("Windows updater is not a regular executable file"));
    }
    validate_path_has_no_reparse_components(&updater)?;
    validate_windows_private_acl(&updater, &updater_metadata)?;

    let canonical_root = fs::canonicalize(root)?;
    let canonical_updater = fs::canonicalize(&updater)?;
    if !canonical_updater.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater must be a private executable beneath the Agent install root",
        ));
    }
    if windows_file_identity(&canonical_updater, false)?.0
        != windows_file_identity(&canonical_root, true)?.0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater must be on the Agent install volume",
        ));
    }

    let installed_executable = root.join("bin").join("hostlink-agent.exe");
    if same_windows_file(&canonical_updater, &installed_executable)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Agent update must be invoked by a separate updater executable",
        ));
    }
    Ok(())
}
