//! Durable Windows update journal format and atomic persistence.

use super::{invalid, is_reparse, transaction_id, validate_identity};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

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

/// Refuse Agent startup while a private offline update journal needs recovery.
/// The caller has already authenticated the current user's install root.
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
    crate::private_fs::windows::validate_acl(
        &updates,
        &metadata,
        crate::private_fs::windows::AllowedPrincipals::OwnerOnly,
        true,
    )?;
    if read_journal(&updates.join("handoff.json"))?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows Agent update journal requires verified recovery before startup",
        ));
    }
    Ok(())
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
