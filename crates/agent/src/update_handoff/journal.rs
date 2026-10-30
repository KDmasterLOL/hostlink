//! Durable Windows update journal format and atomic persistence.

use super::{invalid, is_reparse, transaction_id, validate_identity};
use private_fs::PrivateDir;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read},
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
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Windows update journal has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("Windows update journal has no name"))?;
    PrivateDir::open(parent)
        .and_then(|dir| dir.open_file(name))
        .map_err(io::Error::other)?
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
    PrivateDir::open(&updates).map_err(io::Error::other)?;
    if read_journal(&updates.join("handoff.json"))?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Windows Agent update journal requires verified recovery before startup",
        ));
    }
    Ok(())
}

/// Atomically persist one validated journal phase with file and parent durability.
/// The parent and existing destination must already be private; neither is repaired.
/// An error may mean publication occurred: preserve the transaction and recover from
/// the persisted phase and exact file hashes. The library retains classic Win7 rename.
pub fn write_journal_atomic(path: &Path, journal: &UpdateJournal) -> io::Result<()> {
    journal.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Windows update journal has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("Windows update journal has no name"))?;
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(invalid("Windows update journal exceeds its size limit"));
    }
    PrivateDir::open(parent)
        .and_then(|dir| dir.write_atomic_durable(name, &bytes))
        .map_err(io::Error::other)
}
