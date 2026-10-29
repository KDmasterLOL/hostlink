//! Windows ACL policy shared by Agent jobs, SSH, SFTP, service and updater.

use super::invalid;
use std::{fs, io, path::Path};
use windows_permissions::{
    LocalBox, Sid,
    constants::{AceType, SeObjectType, SecurityInformation},
    wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, ConvertSidToStringSid,
        GetNamedSecurityInfo, SetNamedSecurityInfo,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum AllowedPrincipals {
    OwnerOnly,
    OwnerSystemAdministrators,
}

pub(crate) fn validate_acl(
    path: &Path,
    metadata: &fs::Metadata,
    allowed: AllowedPrincipals,
    protected: bool,
) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    if metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows private path is a reparse point"));
    }
    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows private path owner is not the current Agent user",
        ));
    }
    if protected {
        let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
            &descriptor,
            SecurityInformation::Dacl,
        )
        .map_err(io::Error::other)?;
        if !sddl.to_string_lossy().starts_with("D:P") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows private path DACL inherits permissions",
            ));
        }
    }
    let system: Option<LocalBox<Sid>> = match allowed {
        AllowedPrincipals::OwnerOnly => None,
        AllowedPrincipals::OwnerSystemAdministrators => {
            Some("S-1-5-18".parse().map_err(io::Error::other)?)
        }
    };
    let admins: Option<LocalBox<Sid>> = match allowed {
        AllowedPrincipals::OwnerOnly => None,
        AllowedPrincipals::OwnerSystemAdministrators => {
            Some("S-1-5-32-544".parse().map_err(io::Error::other)?)
        }
    };
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("Windows private path has no DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("Windows private path has an unreadable DACL entry"))?;
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
            .ok_or_else(|| invalid("Windows private path has an allow ACE without SID"))?;
        if sid != current.as_ref()
            && !system.as_ref().is_some_and(|id| sid == id.as_ref())
            && !admins.as_ref().is_some_and(|id| sid == id.as_ref())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows private path grants access to an unexpected SID",
            ));
        }
    }
    Ok(())
}

pub(crate) fn set_acl(path: &Path, directory: bool) -> io::Result<()> {
    use windows_permissions::SecurityDescriptor;

    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let current = ConvertSidToStringSid(&current).map_err(io::Error::other)?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", current.to_string_lossy());
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

// Prevent a SQLite sidecar with another hardlink from being modified while
// hardening its inherited ACL.
pub(crate) fn reject_hardlinks(path: &Path) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let file = fs::File::open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle belongs to the open File and info is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.nNumberOfLinks != 1 {
        return Err(invalid("private file has multiple hard links"));
    }
    Ok(())
}
