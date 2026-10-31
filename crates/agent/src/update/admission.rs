//! Private persistent root and process locks, independent of Apalis tables.

use super::{invalid, private_fs::validate_user_owned_root};
use crate::private_fs::PrivateFileExt;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use std::{fs::File, io, path::Path};

pub(super) fn acquire(root: &Path) -> io::Result<(File, File)> {
    if !root.is_absolute() {
        return Err(invalid("Agent install root must be absolute"));
    }
    validate_user_owned_root(root)?;
    let open = |parent: &Path, name: &str| -> io::Result<File> {
        PrivateDir::open(parent)
            .and_then(|dir| {
                dir.open_file_with(
                    name,
                    OpenOptions {
                        access: FileAccess::ReadWrite,
                        creation: FileCreation::OpenOrCreate,
                        ..OpenOptions::default()
                    },
                )
            })
            .map_err(io::Error::other)?
            .try_clone_std()
    };
    let update = open(root, "update.lock")?;
    update
        .try_lock()
        .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?;
    let runner = open(&root.join("jobs"), "runner.lock")?;
    runner.try_lock().map_err(|error| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("stop the running Agent before updating: {error}"),
        )
    })?;
    ensure_no_legacy_update(root)?;
    #[cfg(windows)]
    super::windows::ensure_offline(root)?;
    Ok((update, runner))
}

/// Reject retired transactions without interpreting, restoring or deleting their contents.
pub(crate) fn ensure_no_legacy_update(root: &Path) -> io::Result<()> {
    // Do not reinterpret transactions left by the retired updater. Never delete them.
    for name in [".updates/publication.json", ".updates/handoff.json"] {
        match std::fs::symlink_metadata(root.join(name)) {
            Ok(_) => {
                return Err(invalid(
                    "legacy update journal requires reconciliation before update",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
