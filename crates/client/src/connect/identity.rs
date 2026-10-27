//! Owner-only Ed25519 identity loading and platform-specific ACL validation.

use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::Path,
};

use russh::keys;

use super::SshClientError;

pub(super) const MAX_IDENTITY_BYTES: usize = 64 * 1024;

pub(super) fn load_identity(path: &Path) -> Result<russh::keys::PrivateKey, SshClientError> {
    if path.as_os_str().is_empty() {
        return Err(SshClientError::Invalid("identity path is empty".into()));
    }
    let mut file = open_identity(path)?;
    validate_identity_file(&file)?;
    let mut contents = Vec::new();
    file.by_ref()
        .take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_IDENTITY_BYTES {
        return Err(SshClientError::Invalid(format!(
            "SSH identity exceeds {MAX_IDENTITY_BYTES} bytes"
        )));
    }
    let contents = std::str::from_utf8(&contents)
        .map_err(|_| SshClientError::Invalid("SSH identity is not UTF-8 OpenSSH text".into()))?;
    let identity = keys::decode_secret_key(contents, None)?;
    if identity.public_key().algorithm().to_string() != "ssh-ed25519" {
        return Err(SshClientError::Invalid(
            "controller identity must be an Ed25519 private key".into(),
        ));
    }
    Ok(identity)
}

fn open_identity(path: &Path) -> Result<File, SshClientError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(SshClientError::Invalid(
            "SSH identity must be a regular non-link file".into(),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT opens a reparse point itself instead of following it.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(SshClientError::Invalid(
            "identity path safety is unsupported on this platform".into(),
        ));
    }

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SshClientError::Invalid(
            "SSH identity must be a regular non-reparse file".into(),
        ));
    }
    Ok(file)
}

pub(crate) fn validate_private_file(file: &File) -> Result<(), SshClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no pointer arguments or memory-safety preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        let mode = metadata.mode() & 0o777;
        if metadata.uid() != effective_uid || mode & 0o077 != 0 {
            return Err(SshClientError::Invalid(format!(
                "SSH identity must be owned by the current user and owner-only (mode {mode:03o})"
            )));
        }
    }
    #[cfg(windows)]
    validate_windows_identity_acl(file)?;
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        return Err(SshClientError::Invalid(
            "identity permission validation is unsupported on this platform".into(),
        ));
    }
    Ok(())
}

fn validate_identity_file(file: &File) -> Result<(), SshClientError> {
    validate_private_file(file)
}

#[cfg(windows)]
fn validate_windows_identity_acl(file: &File) -> Result<(), SshClientError> {
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo,
    };
    use windows_permissions::{LocalBox, Sid};

    // Owner is not included when only DACL is requested from Windows.
    let descriptor = GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )?;
    let current = windows_permissions::utilities::current_process_sid()?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(SshClientError::Invalid(
            "SSH identity must be owned by the current Windows user".into(),
        ));
    }
    let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(SshClientError::Invalid(
            "SSH identity Windows ACL must be protected from inheritance".into(),
        ));
    }
    let dacl = descriptor.dacl().ok_or_else(|| {
        SshClientError::Invalid("SSH identity has no verifiable Windows DACL".into())
    })?;
    let system: LocalBox<Sid> = "S-1-5-18"
        .parse()
        .map_err(|error: std::io::Error| SshClientError::Io(error))?;
    let administrators: LocalBox<Sid> = "S-1-5-32-544"
        .parse()
        .map_err(|error: std::io::Error| SshClientError::Io(error))?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or_else(|| {
            SshClientError::Invalid("SSH identity has an unreadable Windows ACL entry".into())
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
            SshClientError::Invalid("SSH identity has an unverifiable allow ACL entry".into())
        })?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != administrators.as_ref() {
            return Err(SshClientError::Invalid(
                "SSH identity ACL grants access to an unexpected Windows principal".into(),
            ));
        }
    }
    Ok(())
}
