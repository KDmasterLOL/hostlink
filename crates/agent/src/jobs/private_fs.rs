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

/// Check directory entries from / down without first resolving away symlinks.
/// This is a pathname policy check, not an atomic pathname-exec guarantee.
#[cfg(unix)]
pub(super) fn validate_source_ancestors(directory: &Path) -> io::Result<()> {
    use std::path::Component;
    if !directory.is_absolute() {
        return Err(invalid("source ancestors must be absolute"));
    }
    let mut path = PathBuf::new();
    let mut parent = None;
    for component in directory.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(invalid("source ancestors contain path traversal"));
        }
        path.push(component);
        let current = fs::symlink_metadata(&path)?;
        if !current.is_dir() || current.file_type().is_symlink() {
            return Err(invalid("source ancestor is not a non-symlink directory"));
        }
        if let Some(previous) = &parent {
            validate_source_directory(previous, Some(&current))?;
        }
        parent = Some(current);
    }
    let last = parent.ok_or_else(|| invalid("missing source ancestor"))?;
    validate_source_directory(&last, None)?;
    if directory.as_os_str() != directory.canonicalize()?.as_os_str() {
        return Err(invalid(
            "source ancestors must use their exact canonical path",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_source_directory(
    metadata: &fs::Metadata,
    child: Option<&fs::Metadata>,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted source ancestor type or owner",
        ));
    }
    validate_source_directory_ownership(
        metadata.mode(),
        metadata.uid(),
        child.map(fs::Metadata::uid),
    )
}

#[cfg(unix)]
fn validate_source_directory_ownership(
    mode: u32,
    owner: u32,
    child_owner: Option<u32>,
) -> io::Result<()> {
    // SAFETY: geteuid reads the current process identity without pointers.
    let agent = unsafe { libc::geteuid() };
    let trusted = |uid| uid == 0 || uid == agent;
    // A foreign owner can chmod a 0755 directory, so mode bits alone do not
    // prove that its next entry is protected from replacement.
    if !trusted(owner)
        || (mode & 0o022 != 0
            && (mode & 0o1000 == 0 || child_owner.is_none_or(|uid| !trusted(uid))))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source ancestor permits foreign entry replacement",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "ancestor_tests.rs"]
mod ancestor_tests;

pub(crate) fn validate_private_path(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err(invalid(
            "private path is a symlink or has the wrong file type",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads process identity and takes no pointers.
        if metadata.uid() != unsafe { libc::geteuid() }
            || (!directory && metadata.nlink() != 1)
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe owner/private permissions",
            ));
        }
    }
    #[cfg(windows)]
    {
        validate_windows_acl(path, &metadata)?;
        if !directory {
            reject_windows_hardlinks(path)?;
        }
    }
    Ok(())
}

/// Validate link count before touching a SQLite sidecar's DACL. A sidecar can
/// inherit a safe private-directory ACL that needs to be hardened, but an
/// attacker-controlled hardlink must never be modified as part of hardening.
#[cfg(windows)]
pub(super) fn reject_windows_hardlinks(path: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let file = File::open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle belongs to an open File and info is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.nNumberOfLinks != 1 {
        return Err(invalid(
            "private file has multiple hard links; exact ownership cannot be proved",
        ));
    }
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

/// An OS file lock must be explicitly unlocked on drop: forked children may
/// temporarily inherit a duplicate FD, so merely closing ours is insufficient.
#[derive(Debug)]
pub struct FileLease(pub(super) File);

impl std::ops::Deref for FileLease {
    type Target = File;

    fn deref(&self) -> &File {
        &self.0
    }
}

impl Drop for FileLease {
    fn drop(&mut self) {
        if let Err(error) = self.0.unlock() {
            eprintln!("hostlink-agent: failed to release filesystem lock: {error}");
        }
    }
}

/// A single admission/update lock shared by durable admission and the separate updater.
///
/// # Errors
/// Rejects unsafe root/lock paths, private permissions, or filesystem lock failures.
/// Async callers must acquire it on a blocking worker to avoid executor deadlock.
pub fn acquire_update_lock(install_root: &Path) -> io::Result<FileLease> {
    validate_private_path(install_root, true)?;
    exclusive_lock(&install_root.join(UPDATE_LOCK_FILE))
}

pub(super) fn open_lock(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_path(path, false)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = opts.open(path)?;
    restrict_private_path(path, false)?;
    Ok(file)
}

pub(super) fn exclusive_lock(path: &Path) -> io::Result<FileLease> {
    let file = open_lock(path)?;
    file.lock()?;
    Ok(FileLease(file))
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
    validate_windows_acl_contents(path, metadata, true)
}

// SQLite sidecars may inherit the already private parent's ACL when created.
// Validate the same owner/SID allowlist BEFORE protecting their DACL, so no
// foreign allow entry or reparse path is ever silently repaired.
#[cfg(windows)]
pub(super) fn validate_windows_acl_contents(
    path: &Path,
    metadata: &fs::Metadata,
    protected: bool,
) -> io::Result<()> {
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
    if protected && !sddl.to_string_lossy().starts_with("D:P") {
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

/// Harden only a file just created successfully with SFTP CREATE_NEW.
/// Validate inherited ACL ownership/allow ACEs and link identity BEFORE changing it.
#[cfg(windows)]
pub(crate) fn secure_new_upload(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("new upload must be a regular non-symlink file"));
    }
    validate_windows_acl_contents(path, &metadata, false)?;
    reject_windows_hardlinks(path)?;
    restrict_private_path(path, false)
}
