//! Deterministic transaction model for the Windows stopped-runtime updater.
//!
//! Journal and recovery evidence for the bounded Windows offline publication path. Managed
//! service handoff and restart remain outside this module's supported boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

#[cfg(windows)]
use std::fs::OpenOptions;

const JOURNAL_FORMAT: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateIdentity {
    pub target: String,
    pub old_version: String,
    pub old_archive_sha256: String,
    pub old_executable_sha256: String,
    pub old_metadata_sha256: String,
    pub new_version: String,
    pub new_archive_sha256: String,
    pub new_executable_sha256: String,
    pub new_metadata_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdatePhase {
    Staged,
    BackedUp,
    Published,
    Verified,
    Restarted,
    RollingBack,
    RolledBack,
}

/// A journal binds all recovery decisions to exact old and new package identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateJournal {
    format: u32,
    transaction_sha256: String,
    pub phase: UpdatePhase,
    pub identity: UpdateIdentity,
}

impl UpdateJournal {
    /// Create a journal whose identifier is recomputed from the complete package identity.
    pub fn new(identity: UpdateIdentity) -> io::Result<Self> {
        validate_identity(&identity)?;
        let transaction_sha256 = transaction_id(&identity)?;
        Ok(Self {
            format: JOURNAL_FORMAT,
            transaction_sha256,
            phase: UpdatePhase::Staged,
            identity,
        })
    }

    /// Reject malformed or modified journals before using their phase or identity.
    pub fn validate(&self) -> io::Result<()> {
        validate_identity(&self.identity)?;
        if self.format != JOURNAL_FORMAT
            || self.transaction_sha256 != transaction_id(&self.identity)?
        {
            return Err(invalid("Windows update journal identity is inconsistent"));
        }
        Ok(())
    }

    /// Stable transaction identifier used to derive private staged and backup paths.
    #[cfg(windows)]
    pub fn transaction_id(&self) -> &str {
        &self.transaction_sha256
    }

    /// Advance only along the transaction's explicit forward or rollback path.
    pub fn advance(&mut self, next: UpdatePhase) -> io::Result<()> {
        self.validate()?;
        let allowed = matches!(
            (self.phase, next),
            (UpdatePhase::Staged, UpdatePhase::BackedUp)
                | (UpdatePhase::Staged, UpdatePhase::RollingBack)
                | (UpdatePhase::BackedUp, UpdatePhase::Published)
                | (UpdatePhase::Published, UpdatePhase::Verified)
                | (UpdatePhase::Verified, UpdatePhase::Restarted)
                | (UpdatePhase::Restarted, UpdatePhase::RollingBack)
                | (UpdatePhase::BackedUp, UpdatePhase::RollingBack)
                | (UpdatePhase::Published, UpdatePhase::RollingBack)
                | (UpdatePhase::Verified, UpdatePhase::RollingBack)
                | (UpdatePhase::RollingBack, UpdatePhase::RolledBack)
        );
        if !allowed {
            return Err(invalid("illegal Windows update journal phase transition"));
        }
        self.phase = next;
        Ok(())
    }
}

/// Read the bounded handoff journal. The caller must first validate the containing private
/// updater directory and reject reparse points; this function rejects links at the file itself.
pub fn read_journal(path: &Path) -> io::Result<Option<UpdateJournal>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(invalid("Windows update journal is not a regular file"));
    }
    validate_journal_acl(path, &metadata)?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    let journal: UpdateJournal = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Windows update journal is malformed"))?;
    journal.validate()?;
    Ok(Some(journal))
}

/// Atomically persist one validated journal phase in the same directory as its destination.
/// The updater must provide a private, non-reparse parent directory owned by the current user.
#[cfg(not(windows))]
pub fn write_journal_atomic(path: &Path, journal: &UpdateJournal) -> io::Result<()> {
    journal.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Windows update journal has no parent directory"))?;
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(invalid("Windows update journal destination is unsafe"));
        }
        validate_journal_acl(path, &metadata)?;
    }
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    set_private_journal_file(staged.path())?;
    staged.write_all(&bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    sync_parent(parent)
}

/// On Windows, flush the journal bytes and use a same-directory write-through replacement.
#[cfg(windows)]
pub fn write_journal_atomic(path: &Path, journal: &UpdateJournal) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    journal.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Windows update journal has no parent directory"))?;
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(invalid("Windows update journal destination is unsafe"));
        }
        validate_journal_acl(path, &metadata)?;
    }
    let temporary = parent.join(format!(".handoff-{}.tmp", uuid::Uuid::new_v4()));
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    set_private_journal_file(&temporary)?;
    staged.write_all(&bytes)?;
    staged.sync_all()?;
    drop(staged);

    let temporary_wide = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 and share one private parent directory.
    let moved = unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let error = io::Error::last_os_error();
        let cleanup = fs::remove_file(&temporary);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::other(format!(
                "journal replacement failed ({error}); private temporary cleanup failed ({cleanup_error})"
            ))),
        };
    }
    Ok(())
}

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

#[cfg(unix)]
fn set_private_journal_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn validate_journal_acl(path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::GetNamedSecurityInfo;

    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows update journal is not owned by the current user",
        ));
    }
    let sddl = windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )
    .map_err(io::Error::other)?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows update journal ACL inherits permissions",
        ));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("Windows update journal has no DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("Windows update journal DACL entry is unreadable"))?;
        if matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) && ace.sid() != Some(current.as_ref())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows update journal ACL grants access to a foreign owner",
            ));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_journal_acl(_path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn set_private_journal_file(path: &Path) -> io::Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let owner = windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let owner = ConvertSidToStringSid(&owner).map_err(io::Error::other)?;
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{})", owner.to_string_lossy())
            .parse()
            .map_err(io::Error::other)?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .map_err(io::Error::other)
}

#[cfg(not(any(unix, windows)))]
fn set_private_journal_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
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

fn validate_identity(identity: &UpdateIdentity) -> io::Result<()> {
    const WINDOWS_TARGETS: &[&str] = &[
        "x86_64-pc-windows-msvc",
        "x86_64-win7-windows-msvc",
        "i686-win7-windows-msvc",
    ];
    if !WINDOWS_TARGETS.contains(&identity.target.as_str()) {
        return Err(invalid("Windows update journal target is unsupported"));
    }
    semver::Version::parse(&identity.old_version)
        .and_then(|_| semver::Version::parse(&identity.new_version))
        .map_err(|_| invalid("Windows update journal version is malformed"))?;
    for digest in [
        &identity.old_archive_sha256,
        &identity.old_executable_sha256,
        &identity.old_metadata_sha256,
        &identity.new_archive_sha256,
        &identity.new_executable_sha256,
        &identity.new_metadata_sha256,
    ] {
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(invalid("Windows update journal digest is malformed"));
        }
    }
    if identity.old_archive_sha256 == identity.new_archive_sha256
        || identity.old_executable_sha256 == identity.new_executable_sha256
    {
        return Err(invalid(
            "Windows update journal does not describe a binary change",
        ));
    }
    Ok(())
}

fn transaction_id(identity: &UpdateIdentity) -> io::Result<String> {
    let bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> UpdateIdentity {
        UpdateIdentity {
            target: "x86_64-win7-windows-msvc".into(),
            old_version: "1.0.0".into(),
            old_archive_sha256: "a".repeat(64),
            old_executable_sha256: "b".repeat(64),
            old_metadata_sha256: "c".repeat(64),
            new_version: "2.0.0".into(),
            new_archive_sha256: "d".repeat(64),
            new_executable_sha256: "e".repeat(64),
            new_metadata_sha256: "f".repeat(64),
        }
    }

    #[test]
    fn journal_identity_is_deterministic_and_readback_rejects_tampering() {
        let first = UpdateJournal::new(identity()).expect("journal");
        let second = UpdateJournal::new(identity()).expect("journal");
        assert_eq!(first, second);
        first.validate().expect("valid journal");

        let mut changed = first;
        changed.identity.new_executable_sha256 = "1".repeat(64);
        assert!(changed.validate().is_err());
    }

    #[test]
    fn journal_rejects_wrong_target_and_malformed_digest() {
        let mut wrong_target = identity();
        wrong_target.target = "x86_64-pc-windows-gnu".into();
        assert!(UpdateJournal::new(wrong_target).is_err());

        let mut wrong_digest = identity();
        wrong_digest.new_metadata_sha256 = "A".repeat(64);
        assert!(UpdateJournal::new(wrong_digest).is_err());
    }

    #[test]
    fn transitions_are_linear_and_reject_skipped_phases() {
        let mut journal = UpdateJournal::new(identity()).expect("journal");
        assert!(journal.advance(UpdatePhase::Published).is_err());
        for phase in [
            UpdatePhase::BackedUp,
            UpdatePhase::Published,
            UpdatePhase::Verified,
            UpdatePhase::Restarted,
        ] {
            journal.advance(phase).expect("valid forward phase");
        }
        journal
            .advance(UpdatePhase::RollingBack)
            .expect("failed health or registration may roll back after restart");
    }

    #[test]
    fn rollback_transitions_are_explicit_and_terminal() {
        let mut journal = UpdateJournal::new(identity()).expect("journal");
        journal.advance(UpdatePhase::BackedUp).expect("backup");
        journal
            .advance(UpdatePhase::RollingBack)
            .expect("begin rollback");
        journal
            .advance(UpdatePhase::RolledBack)
            .expect("rollback complete");
        assert!(journal.advance(UpdatePhase::BackedUp).is_err());

        let mut restarted = UpdateJournal::new(identity()).expect("journal");
        for phase in [
            UpdatePhase::BackedUp,
            UpdatePhase::Published,
            UpdatePhase::Verified,
            UpdatePhase::Restarted,
        ] {
            restarted.advance(phase).expect("advance to restarted");
        }
        restarted
            .advance(UpdatePhase::RollingBack)
            .expect("restart phase can enter rollback");
        restarted
            .advance(UpdatePhase::RolledBack)
            .expect("rollback completes");
    }

    #[test]
    fn crash_recovery_is_hash_and_phase_bound_and_fail_closed() {
        let old_and_stage = RecoveryEvidence {
            staged_new_valid: true,
            staged_new_metadata_valid: true,
            installed_old_valid: true,
            installed_old_metadata_valid: true,
            ..RecoveryEvidence::default()
        };
        assert_eq!(
            recovery_action(UpdatePhase::Staged, old_and_stage),
            RecoveryAction::CancelUnpublished
        );
        assert_eq!(
            recovery_action(UpdatePhase::Staged, RecoveryEvidence::default()),
            RecoveryAction::PreserveAndError
        );
        let new_and_backup = RecoveryEvidence {
            backup_old_valid: true,
            backup_old_metadata_valid: true,
            installed_new_valid: true,
            installed_new_metadata_valid: true,
            ..RecoveryEvidence::default()
        };
        assert_eq!(
            recovery_action(UpdatePhase::Published, new_and_backup),
            RecoveryAction::VerifyPublished
        );
        assert_eq!(
            recovery_action(
                UpdatePhase::Published,
                RecoveryEvidence {
                    backup_old_valid: true,
                    backup_old_metadata_valid: true,
                    ..RecoveryEvidence::default()
                }
            ),
            RecoveryAction::PreserveAndError
        );
        assert_eq!(
            recovery_action(
                UpdatePhase::Restarted,
                RecoveryEvidence {
                    installed_new_valid: true,
                    installed_new_metadata_valid: true,
                    restarted_new_healthy: false,
                    backup_old_valid: true,
                    backup_old_metadata_valid: true,
                    ..RecoveryEvidence::default()
                }
            ),
            RecoveryAction::RestoreBackup
        );
    }
}

#[cfg(test)]
mod external_regressions {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn identity(old: &[u8], new: &[u8]) -> UpdateIdentity {
        UpdateIdentity {
            target: "x86_64-win7-windows-msvc".into(),
            old_version: "1.0.0".into(),
            old_archive_sha256: "a".repeat(64),
            old_executable_sha256: digest(old),
            old_metadata_sha256: digest(b"old install metadata"),
            new_version: "2.0.0".into(),
            new_archive_sha256: "c".repeat(64),
            new_executable_sha256: digest(new),
            new_metadata_sha256: digest(b"new install metadata"),
        }
    }

    #[test]
    fn persisted_journal_round_trips_and_corrupt_identity_is_rejected() {
        let temp = TempDir::new().expect("temporary updater directory");
        let path = temp.path().join("handoff.json");
        let journal = UpdateJournal::new(identity(b"old", b"new")).expect("valid journal");

        write_journal_atomic(&path, &journal).expect("persist initial phase");
        assert_eq!(read_journal(&path).expect("read journal"), Some(journal));

        let mut journal = UpdateJournal::new(identity(b"old", b"new")).expect("valid journal");
        journal
            .advance(UpdatePhase::BackedUp)
            .expect("advance phase");
        write_journal_atomic(&path, &journal).expect("atomically replace previous phase");
        assert_eq!(
            read_journal(&path).expect("read advanced journal"),
            Some(journal)
        );

        let mut bytes: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("journal bytes")).expect("journal JSON");
        bytes["identity"]["new_executable_sha256"] = serde_json::Value::String("e".repeat(64));
        fs::write(
            &path,
            serde_json::to_vec(&bytes).expect("tampered journal JSON"),
        )
        .expect("tamper journal");
        assert!(read_journal(&path).is_err());
    }

    #[test]
    fn file_hash_evidence_selects_recovery_and_rejects_wrong_installed_digest() {
        let temp = TempDir::new().expect("temporary updater directory");
        let staged = temp.path().join("staged.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let installed = temp.path().join("installed.exe");
        let installed_metadata = temp.path().join("install.json");
        let backup = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&staged, b"new executable").expect("staged executable");
        fs::write(&staged_metadata, b"new install metadata").expect("staged metadata");
        fs::write(&installed, b"new executable").expect("published executable");
        fs::write(&installed_metadata, b"new install metadata").expect("published metadata");
        fs::write(&backup, b"old executable").expect("backup executable");
        fs::write(&backup_metadata, b"old install metadata").expect("backup metadata");
        let identity = identity(b"old executable", b"new executable");
        let paths = TransactionFiles {
            staged_executable: &staged,
            staged_metadata: &staged_metadata,
            installed_executable: &installed,
            installed_metadata: &installed_metadata,
            backup_executable: &backup,
            backup_metadata: &backup_metadata,
        };

        let evidence = inspect_files(&paths, &identity).expect("hash transaction files");
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::VerifyPublished
        );

        // MoveAll can be interrupted after its executable move and before the metadata move.
        // BACKED_UP is durable before either move, so recovery restores the verified old pair.
        fs::write(&installed, b"new executable").expect("simulate swap before journal advance");
        fs::write(&installed_metadata, b"old install metadata").expect("metadata not swapped yet");
        let evidence = inspect_files(&paths, &identity).expect("observe interrupted first swap");
        assert_eq!(
            recovery_action(UpdatePhase::Staged, evidence),
            RecoveryAction::RestoreBackup
        );

        fs::write(&installed, b"unrecognized executable").expect("replace with wrong digest");
        let evidence = inspect_files(&paths, &identity).expect("hash mismatched files");
        assert!(!evidence.installed_old_valid);
        assert!(!evidence.installed_new_valid);
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::PreserveAndError
        );

        fs::write(&backup, b"wrong backup").expect("corrupt backup");
        let evidence = inspect_files(&paths, &identity).expect("hash corrupt backup");
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::PreserveAndError
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_hashing_rejects_symlink_candidates() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("temporary updater directory");
        let old = temp.path().join("old.exe");
        let new = temp.path().join("new.exe");
        let new_metadata = temp.path().join("new-install.json");
        let link = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&old, b"old").expect("old executable");
        fs::write(&new, b"new").expect("new executable");
        fs::write(&new_metadata, b"new install metadata").expect("new metadata");
        symlink(&old, &link).expect("backup symlink");
        fs::write(&backup_metadata, b"old install metadata").expect("backup metadata");
        let identity = identity(b"old", b"new");
        let paths = TransactionFiles {
            staged_executable: &new,
            staged_metadata: &new_metadata,
            installed_executable: &new,
            installed_metadata: &new_metadata,
            backup_executable: &link,
            backup_metadata: &backup_metadata,
        };
        assert!(inspect_files(&paths, &identity).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn offline_publish_failure_after_executable_swap_restores_exact_old_files() {
        let temp = TempDir::new().expect("temporary offline install");
        let staged = temp.path().join("staged.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let installed = temp.path().join("hostlink-agent.exe");
        let installed_metadata = temp.path().join("install.json");
        let backup = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&staged, b"new executable").expect("stage exact new executable");
        fs::write(&staged_metadata, b"new install metadata").expect("stage new metadata");
        fs::write(&installed, b"old executable").expect("installed old executable");
        fs::write(&installed_metadata, b"old install metadata").expect("installed old metadata");
        fs::copy(&installed, &backup).expect("durable old executable backup");
        fs::copy(&installed_metadata, &backup_metadata).expect("durable old metadata backup");

        let identity = identity(b"old executable", b"new executable");
        let journal = UpdateJournal::new(identity.clone()).expect("transaction identity");
        let journal_path = temp.path().join("handoff.json");
        write_journal_atomic(&journal_path, &journal).expect("durable STAGED journal");
        let files = TransactionFiles {
            staged_executable: &staged,
            staged_metadata: &staged_metadata,
            installed_executable: &installed,
            installed_metadata: &installed_metadata,
            backup_executable: &backup,
            backup_metadata: &backup_metadata,
        };
        let before = inspect_files(&files, &identity).expect("verify staged and backup evidence");
        assert_eq!(
            recovery_action(UpdatePhase::Staged, before),
            RecoveryAction::CancelUnpublished
        );

        // Inject a failure after the EXE replacement, before metadata publication or journal advance.
        fs::rename(&staged, &installed).expect("atomic executable swap");
        let interrupted =
            inspect_files(&files, &identity).expect("observe interrupted transaction");
        assert_eq!(
            recovery_action(UpdatePhase::BackedUp, interrupted),
            RecoveryAction::RestoreBackup
        );

        fs::copy(&backup, &installed).expect("rollback exact old executable");
        fs::write(
            &installed_metadata,
            fs::read(&backup_metadata).expect("backup bytes"),
        )
        .expect("rollback exact old metadata");
        let restored = inspect_files(&files, &identity).expect("verify rollback readback");
        assert!(restored.installed_old_valid);
        assert!(restored.installed_old_metadata_valid);
    }

    #[cfg(windows)]
    #[test]
    fn native_self_update_move_all_publishes_rolls_back_and_verifies_acl() {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::{
            ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
        };

        fn sddl(path: &std::path::Path) -> String {
            let descriptor = GetNamedSecurityInfo(
                path.as_os_str(),
                SeObjectType::SE_FILE_OBJECT,
                SecurityInformation::Dacl | SecurityInformation::Owner,
            )
            .expect("read file security descriptor");
            ConvertSecurityDescriptorToStringSecurityDescriptor(
                &descriptor,
                SecurityInformation::Dacl | SecurityInformation::Owner,
            )
            .expect("format file security descriptor")
            .to_string_lossy()
            .into_owned()
        }

        let temp = TempDir::new().expect("disposable Windows update directory");
        let stash = temp.path().join("stash");
        fs::create_dir(&stash).expect("create same-volume stash");
        let installed = temp.path().join("hostlink-agent.exe");
        let installed_metadata = temp.path().join("install.json");
        let staged = temp.path().join("staged-agent.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let restore = temp.path().join("restore-agent.exe");
        let restore_metadata = temp.path().join("restore-install.json");
        fs::write(&installed, b"old executable").expect("write installed executable");
        fs::write(&installed_metadata, b"old metadata").expect("write installed metadata");
        fs::write(&staged, b"new executable").expect("write staged executable");
        fs::write(&staged_metadata, b"new metadata").expect("write staged metadata");
        let staged_acl = sddl(&staged);

        let mut publish = self_update::MoveAll::from_temp(&stash);
        publish
            .add(&staged, &installed)
            .add(&staged_metadata, &installed_metadata);
        publish.commit().expect("publish exact file pair");
        assert_eq!(
            fs::read(&installed).expect("read published image"),
            b"new executable"
        );
        assert_eq!(
            sddl(&installed),
            staged_acl,
            "published image retains the normalized private staging ACL"
        );

        fs::write(&restore, b"old executable").expect("write verified restore image");
        fs::write(&restore_metadata, b"old metadata").expect("write verified restore metadata");
        let rollback_stash = temp.path().join("rollback-stash");
        fs::create_dir(&rollback_stash).expect("create rollback stash");
        let mut rollback = self_update::MoveAll::from_temp(&rollback_stash);
        rollback
            .add(&restore, &installed)
            .add(&restore_metadata, &installed_metadata);
        rollback.commit().expect("restore exact prior file pair");
        assert_eq!(
            fs::read(&installed).expect("read restored image"),
            b"old executable"
        );
        assert_eq!(
            fs::read(&installed_metadata).expect("restored metadata"),
            b"old metadata"
        );

        let failed_first = temp.path().join("failed-first.exe");
        let failed_second = temp.path().join("missing-second.json");
        let failed_dest_first = temp.path().join("failed-dest-first.exe");
        let failed_dest_second = temp.path().join("failed-dest-second.json");
        fs::write(&failed_first, b"new first").expect("new first");
        fs::write(&failed_dest_first, b"old first").expect("old first");
        fs::write(&failed_dest_second, b"old second").expect("old second");
        let mut failing = self_update::MoveAll::from_temp(&stash);
        failing
            .add(&failed_first, &failed_dest_first)
            .add(&failed_second, &failed_dest_second);
        assert!(failing.commit().is_err(), "second source is absent");
        assert_eq!(
            fs::read(failed_dest_first).expect("first rollback"),
            b"old first"
        );
        assert_eq!(
            fs::read(failed_dest_second).expect("second rollback"),
            b"old second"
        );
    }
}
