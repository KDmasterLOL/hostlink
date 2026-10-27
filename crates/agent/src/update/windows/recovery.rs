//! Windows handoff journal recovery before update admission and after interrupted publication.

use super::super::{INSTALL_METADATA, MAX_ENTRY_BYTES, invalid};
use super::fs::validate_windows_private_acl;
use super::publication::{
    cleanup_windows_transaction, rollback_windows, validate_windows_transaction_children,
};
use crate::update::manifest::{read_install_metadata, validate_installed};
use crate::update::private_fs::{hash_file, validate_path_has_no_reparse_components};
use std::{fs, io, path::Path};

#[cfg(windows)]
pub(in crate::update) fn recover_windows_handoff(
    root: &Path,
    force_rollback: bool,
    restarted_new_healthy: bool,
) -> io::Result<()> {
    use crate::update_handoff::{RecoveryAction, TransactionFiles, UpdatePhase};
    use std::os::windows::fs::MetadataExt;

    let updates = root.join(".updates");
    let updates_meta = match fs::symlink_metadata(&updates) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !updates_meta.is_dir()
        || updates_meta.file_type().is_symlink()
        || updates_meta.file_attributes() & 0x400 != 0
    {
        return Err(invalid(
            "Windows updater directory is not a private real directory",
        ));
    }
    validate_windows_private_acl(&updates, &updates_meta)?;
    let journal_path = updates.join("handoff.json");
    let Some(mut journal) = crate::update_handoff::read_journal(&journal_path)? else {
        if fs::read_dir(&updates)?.any(|entry| {
            entry
                .map(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("transaction-")
                })
                .unwrap_or(true)
        }) {
            return Err(invalid(
                "orphaned Windows update transaction artifacts require manual recovery",
            ));
        }
        return Ok(());
    };
    let transaction_dir = updates.join(format!("transaction-{}", journal.transaction_id()));
    let transaction_meta = fs::symlink_metadata(&transaction_dir)?;
    if !transaction_meta.is_dir()
        || transaction_meta.file_type().is_symlink()
        || transaction_meta.file_attributes() & 0x400 != 0
    {
        return Err(invalid("Windows update transaction directory is unsafe"));
    }
    validate_windows_private_acl(&transaction_dir, &transaction_meta)?;
    validate_windows_transaction_children(&transaction_dir, &journal.identity)?;
    let staged_executable = transaction_dir.join("staged-agent.exe");
    let staged_metadata = transaction_dir.join("staged-install.json");
    let backup_executable = transaction_dir.join("backup-agent.exe");
    let backup_metadata = transaction_dir.join("backup-install.json");
    let installed_executable = root.join("bin/hostlink-agent.exe");
    let installed_metadata = root.join(INSTALL_METADATA);
    for path in [
        &staged_executable,
        &staged_metadata,
        &backup_executable,
        &backup_metadata,
        &installed_executable,
        &installed_metadata,
    ] {
        validate_path_has_no_reparse_components(
            path.parent()
                .ok_or_else(|| invalid("recovery candidate has no parent"))?,
        )?;
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || meta.file_attributes() & 0x400 != 0
                {
                    return Err(invalid(
                        "Windows update recovery candidate is not a regular file",
                    ));
                }
                validate_windows_private_acl(path, &meta)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let paths = TransactionFiles {
        staged_executable: &staged_executable,
        staged_metadata: &staged_metadata,
        installed_executable: &installed_executable,
        installed_metadata: &installed_metadata,
        backup_executable: &backup_executable,
        backup_metadata: &backup_metadata,
    };
    let mut evidence = crate::update_handoff::inspect_files(&paths, &journal.identity)?;
    evidence.restarted_new_healthy = restarted_new_healthy;
    if !(evidence.installed_old_valid || evidence.installed_new_valid)
        || !(evidence.installed_old_metadata_valid || evidence.installed_new_metadata_valid)
    {
        return Err(invalid(
            "installed Windows update files do not match either recorded identity",
        ));
    }
    for (path, old_digest, new_digest) in [
        (
            &staged_executable,
            &journal.identity.old_executable_sha256,
            &journal.identity.new_executable_sha256,
        ),
        (
            &staged_metadata,
            &journal.identity.old_metadata_sha256,
            &journal.identity.new_metadata_sha256,
        ),
        (
            &backup_executable,
            &journal.identity.old_executable_sha256,
            &journal.identity.new_executable_sha256,
        ),
        (
            &backup_metadata,
            &journal.identity.old_metadata_sha256,
            &journal.identity.new_metadata_sha256,
        ),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let digest = hash_file(path, MAX_ENTRY_BYTES)?;
                if digest != *old_digest && digest != *new_digest {
                    return Err(invalid(
                        "Windows update candidate does not match either recorded identity",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let action = crate::update_handoff::recovery_action(journal.phase, evidence);
    match action {
        RecoveryAction::CancelUnpublished => {
            if !evidence.installed_old_valid
                || !evidence.installed_old_metadata_valid
                || !evidence.backup_old_valid
                || !evidence.backup_old_metadata_valid
            {
                return Err(invalid(
                    "Windows unpublished transaction lacks verified old files",
                ));
            }
            if !matches!(
                journal.phase,
                UpdatePhase::RollingBack | UpdatePhase::RolledBack
            ) {
                journal.advance(UpdatePhase::RollingBack)?;
                crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
            }
            if journal.phase == UpdatePhase::RollingBack {
                journal.advance(UpdatePhase::RolledBack)?;
                crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
            }
            cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
        }
        RecoveryAction::RestoreBackup => {
            rollback_windows(
                &installed_executable,
                &installed_metadata,
                &backup_executable,
                &backup_metadata,
                &journal_path,
                &mut journal,
            )?;
            cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
        }
        RecoveryAction::FinishRollback => {
            if !evidence.installed_old_valid || !evidence.installed_old_metadata_valid {
                return Err(invalid(
                    "Windows rollback completion lacks the exact old installation",
                ));
            }
            if journal.phase != UpdatePhase::RolledBack {
                if journal.phase != UpdatePhase::RollingBack {
                    journal.advance(UpdatePhase::RollingBack)?;
                    crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
                }
                journal.advance(UpdatePhase::RolledBack)?;
                crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
            }
            cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
        }
        RecoveryAction::VerifyPublished
        | RecoveryAction::StartVerified
        | RecoveryAction::CommitNew => {
            if force_rollback {
                rollback_windows(
                    &installed_executable,
                    &installed_metadata,
                    &backup_executable,
                    &backup_metadata,
                    &journal_path,
                    &mut journal,
                )?;
                return cleanup_windows_transaction(
                    &journal_path,
                    &transaction_dir,
                    &journal.identity,
                );
            }
            let new_metadata = read_install_metadata(&installed_metadata)?;
            if new_metadata.format != 1
                || new_metadata.target != journal.identity.target
                || new_metadata.installed_version != journal.identity.new_version
                || new_metadata.installed_package_sha256 != journal.identity.new_archive_sha256
                || hash_file(&installed_executable, MAX_ENTRY_BYTES)?
                    != journal.identity.new_executable_sha256
            {
                return Err(invalid(
                    "Windows recovered package metadata does not match journal",
                ));
            }
            validate_installed(&root.join("bin"), &new_metadata, &journal.identity.target)?;
            if journal.phase == UpdatePhase::BackedUp {
                journal.advance(UpdatePhase::Published)?;
            }
            if journal.phase == UpdatePhase::Published {
                journal.advance(UpdatePhase::Verified)?;
            }
            crate::update_handoff::write_journal_atomic(&journal_path, &journal)?;
            cleanup_windows_transaction(&journal_path, &transaction_dir, &journal.identity)
        }
        RecoveryAction::PreserveAndError => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows update transaction is ambiguous; journal and candidates preserved",
        )),
    }
}

/// Prevent a login/start command from launching an Agent while a stopped-runtime transaction
/// needs recovery. The caller must already have verified the current user's install root.
#[cfg(windows)]
pub(crate) fn ensure_no_pending_windows_handoff(root: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    let updates = root.join(".updates");
    let metadata = match fs::symlink_metadata(&updates) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x400 != 0
    {
        return Err(invalid(
            "Windows updater directory is not a private real directory",
        ));
    }
    validate_windows_private_acl(&updates, &metadata)?;
    let journal = crate::update_handoff::read_journal(&updates.join("handoff.json"))?;
    if journal.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows Agent update journal requires verified recovery before startup",
        ));
    }
    Ok(())
}
