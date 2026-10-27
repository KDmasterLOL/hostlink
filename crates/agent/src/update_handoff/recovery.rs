//! File identity evidence and fail-closed Windows transaction recovery decisions.

use super::{UpdateIdentity, UpdatePhase, invalid, is_reparse};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

/// Hash the exact staged, installed, and backup files into recovery evidence. Missing files are
/// false; unexpected I/O and links are errors so callers cannot confuse unreadable with absent.
pub fn inspect_files(
    paths: &TransactionFiles<'_>,
    identity: &UpdateIdentity,
) -> io::Result<RecoveryEvidence> {
    Ok(RecoveryEvidence {
        staged_new_valid: matches_digest(paths.staged_executable, &identity.new_executable_sha256)?,
        staged_new_metadata_valid: matches_digest(
            paths.staged_metadata,
            &identity.new_metadata_sha256,
        )?,
        installed_old_valid: matches_digest(
            paths.installed_executable,
            &identity.old_executable_sha256,
        )?,
        installed_old_metadata_valid: matches_digest(
            paths.installed_metadata,
            &identity.old_metadata_sha256,
        )?,
        backup_old_valid: matches_digest(paths.backup_executable, &identity.old_executable_sha256)?,
        backup_old_metadata_valid: matches_digest(
            paths.backup_metadata,
            &identity.old_metadata_sha256,
        )?,
        installed_new_valid: matches_digest(
            paths.installed_executable,
            &identity.new_executable_sha256,
        )?,
        installed_new_metadata_valid: matches_digest(
            paths.installed_metadata,
            &identity.new_metadata_sha256,
        )?,
        restarted_new_healthy: false,
    })
}

/// Paths needed by the file-level recovery planner. Paths are never read from the journal.
pub struct TransactionFiles<'a> {
    pub staged_executable: &'a Path,
    pub staged_metadata: &'a Path,
    pub installed_executable: &'a Path,
    pub installed_metadata: &'a Path,
    pub backup_executable: &'a Path,
    pub backup_metadata: &'a Path,
}

fn matches_digest(path: &Path, expected: &str) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(invalid("Windows update recovery file is not regular"));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()) == expected)
}
/// Hashes and health facts observed from disk/process handles during recovery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryEvidence {
    pub staged_new_valid: bool,
    pub staged_new_metadata_valid: bool,
    pub installed_old_valid: bool,
    pub installed_old_metadata_valid: bool,
    pub backup_old_valid: bool,
    pub backup_old_metadata_valid: bool,
    pub installed_new_valid: bool,
    pub installed_new_metadata_valid: bool,
    pub restarted_new_healthy: bool,
}

/// A side-effect-free recovery decision. Callers must execute it only after validating
/// ownership, ACLs, reparse state, the update lock, and every corresponding file digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    VerifyPublished,
    StartVerified,
    CommitNew,
    RestoreBackup,
    FinishRollback,
    CancelUnpublished,
    PreserveAndError,
}

pub fn recovery_action(phase: UpdatePhase, evidence: RecoveryEvidence) -> RecoveryAction {
    use RecoveryAction as Action;
    use UpdatePhase as Phase;

    if !(evidence.installed_old_valid || evidence.installed_new_valid)
        || !(evidence.installed_old_metadata_valid || evidence.installed_new_metadata_valid)
    {
        return Action::PreserveAndError;
    }

    match phase {
        Phase::Staged if evidence.installed_old_valid && evidence.installed_old_metadata_valid => {
            Action::CancelUnpublished
        }
        Phase::Staged
            if evidence.installed_new_valid
                && evidence.installed_old_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid =>
        {
            Action::RestoreBackup
        }
        Phase::BackedUp
            if evidence.installed_new_valid
                && evidence.installed_new_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid =>
        {
            Action::VerifyPublished
        }
        Phase::BackedUp
            if evidence.installed_old_valid
                && evidence.installed_old_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid
                && evidence.staged_new_valid
                && evidence.staged_new_metadata_valid =>
        {
            Action::CancelUnpublished
        }
        Phase::BackedUp
            if evidence.installed_old_valid
                && evidence.installed_old_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid =>
        {
            Action::CancelUnpublished
        }
        Phase::BackedUp if evidence.backup_old_valid && evidence.backup_old_metadata_valid => {
            Action::RestoreBackup
        }
        Phase::Published
            if evidence.installed_new_valid
                && evidence.installed_new_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid =>
        {
            Action::VerifyPublished
        }
        Phase::Published if evidence.backup_old_valid && evidence.backup_old_metadata_valid => {
            Action::RestoreBackup
        }
        Phase::Verified
            if evidence.installed_new_valid
                && evidence.installed_new_metadata_valid
                && evidence.backup_old_valid
                && evidence.backup_old_metadata_valid =>
        {
            Action::StartVerified
        }
        Phase::Verified
            if evidence.installed_new_valid && evidence.installed_new_metadata_valid =>
        {
            Action::CommitNew
        }
        Phase::Verified if evidence.backup_old_valid && evidence.backup_old_metadata_valid => {
            Action::RestoreBackup
        }
        Phase::Restarted
            if evidence.installed_new_valid
                && evidence.installed_new_metadata_valid
                && evidence.restarted_new_healthy =>
        {
            Action::CommitNew
        }
        Phase::Restarted if evidence.backup_old_valid && evidence.backup_old_metadata_valid => {
            Action::RestoreBackup
        }
        Phase::RollingBack
            if evidence.installed_old_valid && evidence.installed_old_metadata_valid =>
        {
            Action::FinishRollback
        }
        Phase::RollingBack if evidence.backup_old_valid && evidence.backup_old_metadata_valid => {
            Action::RestoreBackup
        }
        Phase::RolledBack
            if evidence.installed_old_valid && evidence.installed_old_metadata_valid =>
        {
            Action::FinishRollback
        }
        _ => Action::PreserveAndError,
    }
}
