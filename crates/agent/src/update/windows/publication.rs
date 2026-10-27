//! Windows stopped-runtime publication, rollback, and transaction cleanup.

use super::super::manifest::{
    InstallMetadata, PackageManifest, read_install_metadata, validate_installed,
};
use super::super::private_fs::{
    hash_file, is_reparse_point, set_private_directory, validate_path_has_no_reparse_components,
};
use super::super::{
    AgentUpdateRequest, INSTALL_METADATA, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, invalid,
    invalid_owned,
};
use super::fs::{
    copy_private_synced, create_private_directory, reject_running_agent, same_windows_file,
    sha256_hex, validate_windows_private_acl, verify_windows_private_file, windows_file_identity,
    write_private_synced,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

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

#[cfg(windows)]
pub(super) fn rollback_windows(
    installed_executable: &Path,
    installed_metadata: &Path,
    backup_executable: &Path,
    backup_metadata: &Path,
    journal_path: &Path,
    journal: &mut crate::update_handoff::UpdateJournal,
) -> io::Result<()> {
    use crate::update_handoff::UpdatePhase;
    if !matches!(
        journal.phase,
        UpdatePhase::RollingBack | UpdatePhase::RolledBack
    ) {
        journal.advance(UpdatePhase::RollingBack)?;
        crate::update_handoff::write_journal_atomic(journal_path, journal)?;
    }
    let identity = &journal.identity;
    if hash_file(backup_executable, MAX_ENTRY_BYTES)? != identity.old_executable_sha256
        || hash_file(backup_metadata, MAX_MANIFEST_BYTES)? != identity.old_metadata_sha256
    {
        return Err(invalid("Windows rollback backup digest mismatch"));
    }
    // Preserve whatever new image is currently installed while restoring the verified old copy.
    let restore_executable = backup_executable.with_extension("restore.exe");
    let restore_metadata = backup_metadata.with_extension("restore.json");
    let restore_executable_needed =
        hash_file(installed_executable, MAX_ENTRY_BYTES)? != identity.old_executable_sha256;
    let restore_metadata_needed =
        hash_file(installed_metadata, MAX_MANIFEST_BYTES)? != identity.old_metadata_sha256;
    if restore_executable_needed {
        if restore_executable.exists() {
            if hash_file(&restore_executable, MAX_ENTRY_BYTES)? != identity.old_executable_sha256 {
                return Err(invalid(
                    "Windows rollback temporary executable has an unknown digest",
                ));
            }
            fs::remove_file(&restore_executable)?;
        }
        copy_private_synced(backup_executable, &restore_executable)?;
    }
    if restore_metadata_needed {
        if restore_metadata.exists() {
            if hash_file(&restore_metadata, MAX_MANIFEST_BYTES)? != identity.old_metadata_sha256 {
                return Err(invalid(
                    "Windows rollback temporary metadata has an unknown digest",
                ));
            }
            fs::remove_file(&restore_metadata)?;
        }
        copy_private_synced(backup_metadata, &restore_metadata)?;
    }
    let rollback_stash = tempfile::Builder::new()
        .prefix("rollback-stash-")
        .tempdir_in(
            backup_executable
                .parent()
                .ok_or_else(|| invalid("Windows rollback backup has no parent"))?,
        )?;
    set_private_directory(rollback_stash.path())?;
    let rollback_stash_metadata = fs::symlink_metadata(rollback_stash.path())?;
    validate_windows_private_acl(rollback_stash.path(), &rollback_stash_metadata)?;
    let mut moves = self_update::MoveAll::from_temp(rollback_stash.path());
    if restore_executable_needed {
        moves.add(&restore_executable, installed_executable);
    }
    if restore_metadata_needed {
        moves.add(&restore_metadata, installed_metadata);
    }
    let move_result = if restore_executable_needed || restore_metadata_needed {
        moves.commit().map_err(|error| error.to_string())
    } else {
        Ok(())
    };
    let inventory_result = (|| {
        if hash_file(installed_executable, MAX_ENTRY_BYTES)? != identity.old_executable_sha256
            || hash_file(installed_metadata, MAX_MANIFEST_BYTES)? != identity.old_metadata_sha256
        {
            return Err(invalid(
                "Windows rollback readback did not match the old inventory",
            ));
        }
        Ok(())
    })();
    if let Err(inventory_error) = inventory_result {
        return Err(io::Error::other(match move_result {
            Ok(()) => inventory_error.to_string(),
            Err(move_error) => format!(
                "self_update rollback returned an error ({move_error}); old inventory verification failed ({inventory_error})"
            ),
        }));
    }
    journal.advance(UpdatePhase::RolledBack)?;
    crate::update_handoff::write_journal_atomic(journal_path, journal)?;
    Ok(())
}

#[cfg(windows)]
fn windows_transaction_candidates() -> [&'static str; 8] {
    [
        "staged-agent.exe",
        "staged-install.json",
        "backup-agent.exe",
        "backup-install.json",
        "backup-agent.restore.exe",
        "backup-install.restore.json",
        "self_update-stash-0",
        "self_update-stash-1",
    ]
}

#[cfg(windows)]
pub(super) fn validate_windows_transaction_children(
    directory: &Path,
    identity: &crate::update_handoff::UpdateIdentity,
) -> io::Result<Vec<(PathBuf, u32, u64)>> {
    use std::os::windows::fs::MetadataExt;

    let allowed = windows_transaction_candidates();
    let mut observed = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("Windows transaction child name is not UTF-8"))?;
        if !allowed.contains(&name) {
            return Err(invalid("Windows transaction contains an unexpected child"));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & 0x400 != 0
        {
            return Err(invalid("Windows transaction child is not a regular file"));
        }
        validate_windows_private_acl(&path, &metadata)?;
        let expected = match name {
            "staged-agent.exe" => &[identity.new_executable_sha256.as_str()][..],
            "staged-install.json" => &[identity.new_metadata_sha256.as_str()][..],
            "backup-agent.exe" | "backup-agent.restore.exe" => {
                &[identity.old_executable_sha256.as_str()][..]
            }
            "backup-install.json" | "backup-install.restore.json" => {
                &[identity.old_metadata_sha256.as_str()][..]
            }
            "self_update-stash-0" => &[
                identity.old_executable_sha256.as_str(),
                identity.new_executable_sha256.as_str(),
            ][..],
            "self_update-stash-1" => &[
                identity.old_metadata_sha256.as_str(),
                identity.new_metadata_sha256.as_str(),
            ][..],
            _ => unreachable!("candidate names were checked against the allowlist"),
        };
        let actual = hash_file(&path, MAX_ENTRY_BYTES)?;
        if !expected.contains(&actual.as_str()) {
            return Err(invalid("Windows transaction child digest is unknown"));
        }
        let (volume, file_index) = windows_file_identity(&path, false)?;
        observed.push((path, volume, file_index));
    }
    Ok(observed)
}

#[cfg(windows)]
pub(super) fn cleanup_windows_transaction(
    journal_path: &Path,
    directory: &Path,
    identity: &crate::update_handoff::UpdateIdentity,
) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    let directory_metadata = fs::symlink_metadata(directory)?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.file_attributes() & 0x400 != 0
    {
        return Err(invalid(
            "Windows transaction directory changed during cleanup",
        ));
    }
    validate_windows_private_acl(directory, &directory_metadata)?;
    let (directory_volume, directory_index) = windows_file_identity(directory, true)?;
    let observed = validate_windows_transaction_children(directory, identity)?;
    let backup_names = ["backup-agent.exe", "backup-install.json"];
    let mut ordered = observed;
    ordered.sort_by_key(|(path, _, _)| {
        u8::from(
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| backup_names.contains(&name)),
        )
    });
    // Remove expendable files first and verified backups last; leave the journal until the
    // transaction directory contains no candidates, so interrupted cleanup remains recoverable.
    for (path, volume, file_index) in ordered {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & 0x400 != 0
            || windows_file_identity(&path, false)? != (volume, file_index)
        {
            return Err(invalid(
                "Windows transaction child identity changed during cleanup",
            ));
        }
        validate_windows_private_acl(&path, &metadata)?;
        fs::remove_file(path)?;
    }
    if fs::read_dir(directory)?.next().is_some() {
        return Err(invalid(
            "Windows transaction directory is not empty after cleanup",
        ));
    }
    let current_directory = fs::symlink_metadata(directory)?;
    if !current_directory.is_dir()
        || current_directory.file_type().is_symlink()
        || current_directory.file_attributes() & 0x400 != 0
        || windows_file_identity(directory, true)? != (directory_volume, directory_index)
    {
        return Err(invalid(
            "Windows transaction directory identity changed during cleanup",
        ));
    }
    validate_windows_private_acl(directory, &current_directory)?;
    fs::remove_file(journal_path)?;
    fs::remove_dir(directory)
}
