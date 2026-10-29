//! Linux offline publication and crash recovery.

use super::manifest::{PackageManifest, package_files};
use super::{
    AgentUpdateRequest, INSTALL_METADATA, PublicationJournal, invalid, invalid_owned,
    supported_targets, target_matches_runtime,
};
use crate::update::manifest::{InstallMetadata, read_install_metadata, validate_installed};
use crate::update::private_fs::{
    create_private_directory, is_reparse_point, open_private_file, set_private_directory,
    sync_directory, validate_private_directory, write_atomic,
};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path},
};

#[cfg(not(windows))]
pub(super) fn publish_linux(
    root: &Path,
    bin_root: &Path,
    metadata_path: &Path,
    request: &AgentUpdateRequest,
    manifest: PackageManifest,
    old_metadata: InstallMetadata,
    staged: tempfile::TempDir,
) -> io::Result<()> {
    let updates = root.join(".updates");
    create_private_directory(&updates)?;
    let backup = updates.join(format!(
        "backup-{}-{}",
        old_metadata.installed_version, old_metadata.installed_package_sha256
    ));
    if backup.exists() {
        return Err(invalid(
            "a recoverable Agent backup already exists; refusing to overwrite it",
        ));
    }
    let journal_path = updates.join("publication.json");
    let staged_package = staged
        .path()
        .join("extracted")
        .join(format!("hostlink-agent-{}", request.target));
    let staged_bin = staged.path().join("bin");
    fs::create_dir(&staged_bin)?;
    set_private_directory(&staged_bin)?;
    for name in package_files(&request.target) {
        let source = staged_package.join(&name);
        let dest = staged_bin.join(&name);
        fs::rename(source, dest)?;
    }
    validate_installed(
        &staged_bin,
        &InstallMetadata {
            format: 1,
            target: request.target.clone(),
            installed_version: request.version.clone(),
            installed_package_sha256: request.archive_sha256.clone(),
            installed_files: manifest.files.clone(),
        },
        &request.target,
    )?;

    let journal = PublicationJournal {
        format: 1,
        backup: backup
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid Agent backup path"))?
            .to_owned(),
        old_metadata: old_metadata.clone(),
    };
    write_atomic(
        &journal_path,
        &serde_json::to_vec(&journal).map_err(io::Error::other)?,
    )?;

    fs::rename(bin_root, &backup)?;
    if let Err(error) = fs::rename(&staged_bin, bin_root) {
        let rollback = fs::rename(&backup, bin_root);
        if let Err(rollback_error) = rollback {
            return Err(io::Error::other(format!(
                "Agent publication failed ({error}); rollback failed ({rollback_error}); old executable remains at {}",
                backup.display()
            )));
        }
        sync_directory(root)?;
        sync_directory(&updates)?;
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    sync_directory(root)?;
    sync_directory(&updates)?;
    let metadata = InstallMetadata {
        format: 1,
        target: request.target.clone(),
        installed_version: request.version.clone(),
        installed_package_sha256: request.archive_sha256.clone(),
        installed_files: manifest.files,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
    if let Err(error) = write_atomic(metadata_path, &metadata_bytes) {
        let failed = root
            .join(".updates")
            .join(format!("failed-{}", request.archive_sha256));
        let preserve_new = fs::rename(bin_root, &failed);
        if let Err(preserve_error) = preserve_new {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); new files could not be preserved ({preserve_error}) and old backup remains at {}",
                backup.display()
            )));
        }
        let restore_old = fs::rename(&backup, bin_root);
        if let Err(rollback_error) = restore_old {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); rollback failed ({rollback_error}); preserve files in {} and {}",
                backup.display(),
                failed.display()
            )));
        }
        sync_directory(root)?;
        sync_directory(&updates)?;
        if let Err(metadata_error) = write_atomic(
            metadata_path,
            &serde_json::to_vec_pretty(&old_metadata).map_err(io::Error::other)?,
        ) {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); old binary was restored but old metadata restoration failed ({metadata_error}); journal remains at {}",
                journal_path.display()
            )));
        }
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    let verification = read_install_metadata(metadata_path).and_then(|installed| {
        if installed != metadata {
            return Err(invalid(
                "installed Agent metadata differs from the selected package",
            ));
        }
        validate_installed(bin_root, &installed, &request.target)
    });
    if let Err(error) = verification {
        let failed = updates.join(format!("verification-failed-{}", request.archive_sha256));
        fs::rename(bin_root, &failed).map_err(|preserve_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); new files could not be preserved ({preserve_error}); old backup remains at {}",
                backup.display()
            ))
        })?;
        fs::rename(&backup, bin_root).map_err(|rollback_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); rollback failed ({rollback_error}); preserve files in {} and {}",
                backup.display(),
                failed.display()
            ))
        })?;
        write_atomic(
            metadata_path,
            &serde_json::to_vec_pretty(&old_metadata).map_err(io::Error::other)?,
        )
        .map_err(|metadata_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); old binary was restored but metadata rollback failed ({metadata_error}); journal remains at {}",
                journal_path.display()
            ))
        })?;
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    File::open(root)?.sync_all()?;
    File::open(&updates)?.sync_all()?;
    fs::remove_file(journal_path)?;
    File::open(&updates)?.sync_all()?;
    Ok(())
}
#[cfg(not(windows))]
pub(super) fn recover_interrupted_publication(root: &Path) -> io::Result<()> {
    let updates = root.join(".updates");
    match fs::symlink_metadata(&updates) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata)
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata) =>
        {
            return Err(invalid("Agent update recovery directory is unsafe"));
        }
        Ok(metadata) => validate_private_directory(&updates, &metadata)?,
    }
    let journal_path = updates.join("publication.json");
    match fs::symlink_metadata(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata) =>
        {
            Err(invalid("Agent update recovery journal is unsafe"))
        }
        Ok(_) => {
            let file = open_private_file(&journal_path, false)?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err(invalid("Agent recovery journal exceeds its size limit"));
            }
            let journal: PublicationJournal = serde_json::from_slice(&bytes).map_err(|error| {
                invalid_owned(format!("invalid Agent recovery journal: {error}"))
            })?;
            if journal.format != 1
                || !journal.backup.starts_with("backup-")
                || Path::new(&journal.backup).components().count() != 1
                || !matches!(
                    Path::new(&journal.backup).components().next(),
                    Some(Component::Normal(_))
                )
                || !supported_targets().contains(&journal.old_metadata.target.as_str())
                || !target_matches_runtime(&journal.old_metadata.target)
            {
                return Err(invalid(
                    "Agent recovery journal contains an unsafe backup path",
                ));
            }
            let backup = updates.join(&journal.backup);
            let bin = root.join("bin");
            let metadata_path = root.join(INSTALL_METADATA);
            let installed = read_install_metadata(&metadata_path).and_then(|metadata| {
                validate_installed(&bin, &metadata, &journal.old_metadata.target).map(|()| metadata)
            });
            if installed.is_ok() {
                fs::remove_file(&journal_path)?;
                File::open(&updates)?.sync_all()?;
                return Ok(());
            }
            if validate_installed(&bin, &journal.old_metadata, &journal.old_metadata.target).is_ok()
            {
                write_atomic(
                    &metadata_path,
                    &serde_json::to_vec_pretty(&journal.old_metadata).map_err(io::Error::other)?,
                )?;
                fs::remove_file(&journal_path)?;
                File::open(&updates)?.sync_all()?;
                return Ok(());
            }
            if !backup.exists() {
                return Err(io::Error::other(format!(
                    "Agent update recovery cannot validate installed files or find backup {}; journal remains at {}",
                    backup.display(),
                    journal_path.display()
                )));
            }
            validate_installed(&backup, &journal.old_metadata, &journal.old_metadata.target)
                .map_err(|error| io::Error::other(format!(
                    "Agent update recovery backup {} failed integrity validation ({error}); journal remains at {}",
                    backup.display(), journal_path.display()
                )))?;
            if bin.exists() {
                let failed = updates.join(format!("recovery-failed-{}", std::process::id()));
                if failed.exists() {
                    return Err(invalid(
                        "Agent recovery destination already exists; backup and journal preserved",
                    ));
                }
                fs::rename(&bin, &failed)?;
                sync_directory(root)?;
                sync_directory(&updates)?;
            }
            fs::rename(&backup, &bin)?;
            sync_directory(root)?;
            sync_directory(&updates)?;
            write_atomic(
                &metadata_path,
                &serde_json::to_vec_pretty(&journal.old_metadata).map_err(io::Error::other)?,
            )?;
            File::open(root)?.sync_all()?;
            fs::remove_file(&journal_path)?;
            File::open(&updates)?.sync_all()?;
            Ok(())
        }
    }
}
