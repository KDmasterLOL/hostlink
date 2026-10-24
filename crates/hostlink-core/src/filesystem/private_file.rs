//! Cross-platform private file and directory permission primitives.
//!
//! Unix owns privacy through POSIX mode bits. Windows uses native security APIs via
//! `windows-permissions`; no shell, PowerShell, or `icacls.exe` protocol participates in
//! secret-file correctness.

use std::io;
use std::path::{Path, PathBuf};

pub(crate) fn validate_private_directory_handle(
    directory: &cap_std::fs::Dir,
) -> PrivatePathResult<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;

        let metadata = directory
            .dir_metadata()
            .map_err(|source| io_error(Path::new("<opened private directory>"), source))?;
        if !metadata.is_dir() {
            return Err(PrivatePathError::Invalid(
                "private append ownership boundary is not a directory".to_owned(),
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(PrivatePathError::Invalid(format!(
                "private append ownership directory must not be group/world-accessible (mode {mode:03o})"
            )));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::GetSecurityInfo;

        let descriptor = GetSecurityInfo(
            directory,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl,
        )
        .map_err(|source| io_error(Path::new("<opened private directory>"), source))?;
        validate_windows_private_descriptor(&descriptor, "<opened private directory>")
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = directory;
        Err(PrivatePathError::Invalid(
            "private-directory permission validation is unsupported on this platform".to_owned(),
        ))
    }
}

pub(crate) fn restrict_private_file_handle(file: &mut std::fs::File) -> PrivatePathResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(Path::new("<opened private file>"), source))
    }

    #[cfg(windows)]
    {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::SetSecurityInfo;
        use windows_permissions::{LocalBox, SecurityDescriptor};

        let current = current_windows_sid()?;
        let current = windows_permissions::wrappers::ConvertSidToStringSid(&current)
            .map_err(|source| io_error(Path::new("<opened private file>"), source))?;
        let descriptor: LocalBox<SecurityDescriptor> =
            private_windows_sddl(&current.to_string_lossy(), false)
                .parse()
                .map_err(|source| io_error(Path::new("<opened private file>"), source))?;
        let dacl = descriptor.dacl().ok_or_else(|| {
            PrivatePathError::Invalid("failed to construct private Windows file DACL".to_owned())
        })?;
        SetSecurityInfo(
            file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
        .map_err(|source| io_error(Path::new("<opened private file>"), source))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(PrivatePathError::Invalid(
            "private-file permission enforcement is unsupported on this platform".to_owned(),
        ))
    }
}

/// Failure returned by private-path permission validation/enforcement.
#[derive(Debug, thiserror::Error)]
pub enum PrivatePathError {
    /// Reading or updating the target path failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path associated with the failed operation.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
    /// The path exists but violates the required private permission/ACL contract.
    #[error("{0}")]
    Invalid(String),
}

/// Result type for private file/directory operations.
pub type PrivatePathResult<T> = std::result::Result<T, PrivatePathError>;

/// Validates that an existing file is private to the current user/process authority.
///
/// Unix rejects any group/world permission bits. Windows rejects inherited or unexpected ACL
/// principals instead of relying on shell tooling.
///
/// # Errors
///
/// Returns [`PrivatePathError`] when metadata/ACL inspection fails, the permission contract is
/// unsafe, or the target platform has no supported privacy model.
pub fn validate_private_file(path: &Path) -> PrivatePathResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path)
            .map_err(|source| io_error(path, source))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(PrivatePathError::Invalid(format!(
                "private file {} must not be group/world-accessible (mode {:03o}); run chmod 600 {}",
                path.display(),
                mode,
                path.display()
            )));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        validate_windows_private_file(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(PrivatePathError::Invalid(format!(
            "private-file permission validation is unsupported on this platform for {}",
            path.display()
        )))
    }
}

/// Replaces an existing file's permissions with the toolkit private-file contract.
///
/// Unix applies mode `0600`. Windows installs a protected DACL granting full access only to the
/// current user authority.
///
/// # Errors
///
/// Returns [`PrivatePathError`] when the permission/ACL update fails or the platform is unsupported.
pub fn restrict_private_file(path: &Path) -> PrivatePathResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(path, source))
    }

    #[cfg(windows)]
    {
        restrict_windows_path(path, false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(PrivatePathError::Invalid(format!(
            "private-file permission enforcement is unsupported on this platform for {}",
            path.display()
        )))
    }
}

/// Replaces an existing directory's permissions with the toolkit private-directory contract.
///
/// Unix applies mode `0700`. Windows installs a protected inheritable DACL for the current user so
/// newly created descendants remain inside the private authority boundary.
///
/// # Errors
///
/// Returns [`PrivatePathError`] when the permission/ACL update fails or the platform is unsupported.
pub fn restrict_private_directory(path: &Path) -> PrivatePathResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(path, source))
    }

    #[cfg(windows)]
    {
        restrict_windows_path(path, true)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(PrivatePathError::Invalid(format!(
            "private-directory permission enforcement is unsupported on this platform for {}",
            path.display()
        )))
    }
}

fn io_error(path: &Path, source: io::Error) -> PrivatePathError {
    PrivatePathError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(windows)]
fn current_windows_sid()
-> PrivatePathResult<windows_permissions::LocalBox<windows_permissions::Sid>> {
    windows_permissions::utilities::current_process_sid()
        .map_err(|source| io_error(Path::new("<current Windows process token>"), source))
}

#[cfg(any(windows, test))]
fn private_windows_sddl(current_sid: &str, directory: bool) -> String {
    let ace_flags = if directory { "OICI" } else { "" };
    format!("D:P(A;{ace_flags};FA;;;{current_sid})")
}

#[cfg(windows)]
fn restrict_windows_path(path: &Path, directory: bool) -> PrivatePathResult<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current = current_windows_sid()?;
    let current = ConvertSidToStringSid(&current).map_err(|source| io_error(path, source))?;
    let descriptor: LocalBox<SecurityDescriptor> =
        private_windows_sddl(&current.to_string_lossy(), directory)
            .parse()
            .map_err(|source| io_error(path, source))?;
    let dacl = descriptor.dacl().ok_or_else(|| {
        PrivatePathError::Invalid(format!(
            "failed to construct private Windows DACL for {}",
            path.display()
        ))
    })?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(|source| io_error(path, source))
}

#[cfg(windows)]
fn validate_windows_private_file(path: &Path) -> PrivatePathResult<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::GetNamedSecurityInfo;

    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
    )
    .map_err(|source| io_error(path, source))?;
    validate_windows_private_descriptor(&descriptor, &format!("private file {}", path.display()))
}

#[cfg(windows)]
fn validate_windows_private_descriptor(
    descriptor: &windows_permissions::SecurityDescriptor,
    context: &str,
) -> PrivatePathResult<()> {
    use windows_permissions::constants::{AceType, SecurityInformation};
    use windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor;
    use windows_permissions::{LocalBox, Sid};

    let sddl_buffer =
        ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, SecurityInformation::Dacl)
            .map_err(|source| io_error(Path::new(context), source))?;
    let sddl = sddl_buffer.to_string_lossy();
    if !sddl.starts_with("D:P") {
        return Err(PrivatePathError::Invalid(format!(
            "{context} has an unsafe Windows ACL: inheritance is enabled"
        )));
    }

    let current = current_windows_sid()?;
    let system: LocalBox<Sid> = "S-1-5-18"
        .parse()
        .map_err(|source| io_error(Path::new(context), source))?;
    let administrators: LocalBox<Sid> = "S-1-5-32-544"
        .parse()
        .map_err(|source| io_error(Path::new(context), source))?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| PrivatePathError::Invalid(format!("{context} has no Windows DACL")))?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or_else(|| {
            PrivatePathError::Invalid(format!(
                "{context} has an unreadable Windows ACE at index {index}"
            ))
        })?;
        let is_allow = matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        );
        if !is_allow {
            continue;
        }
        let sid = ace.sid().ok_or_else(|| {
            PrivatePathError::Invalid(format!(
                "{context} has an allow ACE without a verifiable SID"
            ))
        })?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != administrators.as_ref() {
            return Err(PrivatePathError::Invalid(format!(
                "{context} has an unexpected Windows allow ACE"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn private_windows_sddl_is_protected_and_directory_inheritable() {
        assert_eq!(
            private_windows_sddl("S-1-5-21-42", false),
            "D:P(A;;FA;;;S-1-5-21-42)"
        );
        assert_eq!(
            private_windows_sddl("S-1-5-21-42", true),
            "D:P(A;OICI;FA;;;S-1-5-21-42)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_file_validation_rejects_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("secret.env");
        std::fs::write(&path, b"secret").expect("write secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert!(validate_private_file(&path).is_err());
        restrict_private_file(&path).expect("restrict secret");
        validate_private_file(&path).expect("validate restricted secret");
    }

    #[cfg(windows)]
    #[test]
    fn private_file_validation_rejects_inherited_acl_then_accepts_restricted_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("secret.env");
        std::fs::write(&path, b"secret").expect("write secret");
        assert!(
            validate_private_file(&path).is_err(),
            "fresh temp file should still inherit a broader parent ACL"
        );
        restrict_private_file(&path).expect("restrict secret");
        validate_private_file(&path).expect("validate restricted secret");
    }
}
