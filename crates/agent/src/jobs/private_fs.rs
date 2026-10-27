use super::*;

pub(super) fn validate_digest(value: &str) -> io::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "SHA-256 digest must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn validate_private_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory {
        return Err(invalid(
            "private path is a symlink or has the wrong file type",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owner/private permissions",
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_acl(path, &metadata)?;
    Ok(())
}

pub(crate) fn restrict_private_path(path: &Path, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    set_private_windows_acl(path, directory)?;
    validate_private_path(path, directory)
}

pub(super) fn write_new_private(path: &Path, value: &JobRecord) -> io::Result<()> {
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    if data.len() > MAX_RECORD_BYTES {
        return Err(invalid("serialized job record exceeds size limit"));
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    restrict_private_path(path, false)?;
    file.write_all(&data)?;
    file.sync_all()?;
    sync_directory(path.parent().expect("created job file has a parent"))
}

pub(super) fn read_bounded_private(path: &Path) -> io::Result<Vec<u8>> {
    validate_private_path(path, false)?;
    let mut input = File::open(path)?.take(MAX_RECORD_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(invalid("job state exceeded its maximum size"));
    }
    Ok(bytes)
}

pub(super) fn atomic_replace_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_RECORD_BYTES {
        return Err(invalid("job record exceeds maximum size"));
    }
    validate_private_path(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("record has no parent"))?;
    let mut stage = tempfile::NamedTempFile::new_in(parent)?;
    restrict_private_path(stage.path(), false)?;
    stage.write_all(data)?;
    stage.as_file().sync_all()?;
    stage.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

/// A single admission/update lock shared by JobStore and the separate updater.
pub fn acquire_update_lock(install_root: &Path) -> io::Result<File> {
    validate_private_path(install_root, true)?;
    exclusive_lock(&install_root.join(UPDATE_LOCK_FILE))
}

pub(super) fn exclusive_lock(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(invalid("lock file is not a regular file"));
    }
    let file = opts.open(path)?;
    restrict_private_path(path, false)?;
    file.lock()?;
    Ok(file)
}

pub(super) fn sync_directory(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

#[cfg(windows)]
pub(super) fn validate_windows_acl(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
    };
    use windows_permissions::{LocalBox, Sid};
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows private path is a reparse point"));
    }
    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let sddl =
        ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, SecurityInformation::Dacl)
            .map_err(io::Error::other)?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows ACL inherits permissions",
        ));
    }
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows private path owner does not match current Agent user",
        ));
    }
    let system: LocalBox<Sid> = "S-1-5-18".parse().map_err(io::Error::other)?;
    let admins: LocalBox<Sid> = "S-1-5-32-544".parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("private path missing Windows DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("unreadable Windows DACL entry"))?;
        if !matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        let sid = ace
            .sid()
            .ok_or_else(|| invalid("unverifiable Windows ACE"))?;
        if sid != current.as_ref() && sid != system.as_ref() && sid != admins.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "foreign Windows ACL allow entry",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn set_private_windows_acl(path: &Path, directory: bool) -> io::Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let current = ConvertSidToStringSid(&current).map_err(io::Error::other)?;
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{flags};FA;;;{})", current.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("cannot create private Windows DACL"))?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(io::Error::other)
}
