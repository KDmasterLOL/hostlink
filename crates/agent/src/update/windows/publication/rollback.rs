//! Windows publication rollback.

#[cfg(windows)]
use super::super::super::private_fs::hash_file;
#[cfg(windows)]
use super::super::super::{MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, invalid};
#[cfg(windows)]
use super::super::fs::copy_private_synced;
use crate::update::staging::PrivateTempDir;
#[cfg(windows)]
use std::{fs, io, path::Path};

#[cfg(windows)]
pub(in crate::update::windows) fn rollback_windows(
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
    let mut rollback_stash = PrivateTempDir::new_in(
        backup_executable
            .parent()
            .ok_or_else(|| invalid("Windows rollback backup has no parent"))?,
        "rollback-stash-",
    )?;
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
        // Failed restoration is ambiguous: retain displaced images for investigation.
        rollback_stash.preserve();
        return Err(io::Error::other(match move_result {
            Ok(()) => format!(
                "{inventory_error}; preserve rollback stash at {}",
                rollback_stash.path().display()
            ),
            Err(move_error) => format!(
                "self_update rollback returned an error ({move_error}); old inventory verification failed ({inventory_error}); preserve rollback stash at {}",
                rollback_stash.path().display()
            ),
        }));
    }
    journal.advance(UpdatePhase::RolledBack)?;
    crate::update_handoff::write_journal_atomic(journal_path, journal)?;
    Ok(())
}
