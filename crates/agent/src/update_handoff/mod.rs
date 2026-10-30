//! Durable journal and deterministic recovery model for Windows Agent updates.

use sha2::{Digest, Sha256};
use std::{fs, io};

mod journal;
mod recovery;
#[cfg(test)]
mod tests;

#[cfg(windows)]
pub(crate) use journal::ensure_no_pending_windows_handoff;
pub(crate) use journal::{
    UpdateIdentity, UpdateJournal, UpdatePhase, read_journal, write_journal_atomic,
};
#[cfg(test)]
pub(crate) use recovery::RecoveryEvidence;
pub(crate) use recovery::{RecoveryAction, TransactionFiles, inspect_files, recovery_action};

pub(super) fn validate_identity(identity: &UpdateIdentity) -> io::Result<()> {
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

pub(super) fn transaction_id(identity: &UpdateIdentity) -> io::Result<String> {
    let bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(windows)]
pub(super) fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
pub(super) fn is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}
