use super::*;

#[cfg(windows)]
pub(super) fn reject_windows_parent_reparse_components(parent: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::path::{Component, Prefix};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if !parent.is_absolute() {
        return Err(invalid("Agent install root parent must be absolute"));
    }
    let mut ancestor = PathBuf::new();
    for component in parent.components() {
        match component {
            Component::Prefix(prefix) => {
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(invalid(
                        "Agent install root must be on a local Windows drive",
                    ));
                }
                ancestor.push(component.as_os_str());
            }
            Component::RootDir => ancestor.push(component.as_os_str()),
            Component::CurDir | Component::ParentDir => {
                return Err(invalid("Agent install root parent contains path traversal"));
            }
            Component::Normal(_) => {
                ancestor.push(component.as_os_str());
                let metadata = fs::symlink_metadata(&ancestor)?;
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(invalid(
                        "Agent install root parent contains a symlink or reparse point",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn reject_elevated_user() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must run as a normal user",
            ));
        }
    }
    #[cfg(windows)]
    if !crate::private_fs::windows::is_non_elevated_user()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "enrollment must not run elevated or as SYSTEM",
        ));
    }
    Ok(())
}
