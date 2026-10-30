//! Validation and cleanup of Windows publication transaction files.

#[cfg(windows)]
use super::super::super::private_fs::hash_file;
#[cfg(windows)]
use super::super::super::{MAX_ENTRY_BYTES, invalid};
#[cfg(windows)]
use super::super::fs::{verify_windows_private_path, windows_file_identity};
#[cfg(windows)]
use std::{
    fs, io,
    path::{Path, PathBuf},
};

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
pub(in crate::update::windows) fn validate_windows_transaction_children(
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
        verify_windows_private_path(&path, &metadata)?;
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
pub(in crate::update::windows) fn cleanup_windows_transaction(
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
    verify_windows_private_path(directory, &directory_metadata)?;
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
        verify_windows_private_path(&path, &metadata)?;
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
    verify_windows_private_path(directory, &current_directory)?;
    fs::remove_file(journal_path)?;
    fs::remove_dir(directory)
}
