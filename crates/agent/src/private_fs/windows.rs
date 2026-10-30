//! Windows ACL policy shared by Agent jobs, SSH, SFTP, service and updater.

use super::invalid;
pub(crate) use super::restrict_private_path as set_acl;
use std::{
    fs, io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
};
use windows_permissions::{
    LocalBox, SecurityDescriptor,
    constants::{AceType, SeObjectType::SE_FILE_OBJECT, SecurityInformation},
    utilities::{current_process_sid, os_from_buf},
    wrappers::{
        ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo, SetSecurityInfo,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum AllowedPrincipals {
    OwnerOnly,
    OwnerSystemAdministrators,
}

/// OS-resolved profile path, independent of caller-supplied environment variables.
/// SHGetFolderPathW is available on NT6.1 and avoids the Windows 7 combase import.
pub(crate) fn local_app_data_path() -> io::Result<PathBuf> {
    use windows_sys::Win32::UI::Shell::{CSIDL_LOCAL_APPDATA, SHGetFolderPathW};

    let mut buffer = [0u16; 260];
    // SAFETY: SHGetFolderPathW writes at most MAX_PATH UTF-16 units into this buffer.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            CSIDL_LOCAL_APPDATA as i32,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    windows::core::HRESULT(result)
        .ok()
        .map_err(io::Error::other)?;
    PathBuf::from(os_from_buf(&buffer)).canonicalize()
}

/// Canonical owned Agent root shared by the service and the stopped updater.
/// No application/enrollment/schema validation occurs at this filesystem boundary.
pub(crate) fn validate_agent_root(path: &Path) -> io::Result<PathBuf> {
    if !is_non_elevated_user()? {
        return Err(invalid(
            "Agent service/update requires a non-elevated Windows user",
        ));
    }
    let directory = super::open_directory(path)?;
    let root = path.canonicalize()?;
    let profile = local_app_data_path()?;
    let relative = root
        .strip_prefix(&profile)
        .map_err(|_| invalid("Agent root must be beneath the current user's LocalAppData"))?;
    if relative.as_os_str().is_empty() {
        return Err(invalid("Agent root cannot be LocalAppData itself"));
    }
    // Trust the OS profile boundary, not arbitrary intermediate directories.
    // cap-std rejects reparse components; the private parent prevents root replacement.
    let parent = directory.open_parent_dir(cap_std::ambient_authority())?;
    validate_file_acl(
        &directory.into_std_file(),
        AllowedPrincipals::OwnerOnly,
        true,
    )?;
    if root.parent() != Some(profile.as_path()) {
        validate_file_acl(&parent.into_std_file(), AllowedPrincipals::OwnerOnly, true)?;
    }
    Ok(root)
}

/// Authoritative user-scope decision for Agent execution, enrollment and
/// service management. Windows token ownership and elevation are independent.
pub(crate) fn is_non_elevated_user() -> io::Result<bool> {
    use windows_sys::Win32::{
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    if matches!(
        current_process_sid()?.to_string().as_str(),
        "S-1-5-18" | "S-1-5-19" | "S-1-5-20"
    ) {
        return Ok(false);
    }
    let mut raw = std::ptr::null_mut();
    // SAFETY: the current process pseudo-handle is valid; raw is an out parameter.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned an exclusively owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    // SAFETY: the owned handle remains valid, and elevation and returned are writable.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated == 0)
}

pub(crate) fn validate_acl(
    path: &Path,
    allowed: AllowedPrincipals,
    protected: bool,
) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let file = super::open_path(path, false)?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows private path is a reparse point"));
    }
    validate_file_acl(&file, allowed, protected)
}

pub(super) fn validate_file_acl(
    file: &fs::File,
    allowed: AllowedPrincipals,
    protected: bool,
) -> io::Result<()> {
    let descriptor = GetSecurityInfo(
        file,
        SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )?;
    let current = current_process_sid()?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows private path owner is not the current Agent user",
        ));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("Windows private path has no DACL"))?;
    let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )?;
    if protected && !sddl.to_string_lossy().starts_with("D:P") {
        return Err(invalid("Windows private path DACL inherits permissions"));
    }
    if dacl.len() == 0 {
        return Err(invalid("Windows private path has an empty DACL"));
    }
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("unreadable ACL entry"))?;
        // Deny ACEs cannot expose a file to a different account.
        if matches!(
            ace.ace_type(),
            AceType::ACCESS_DENIED_ACE_TYPE
                | AceType::ACCESS_DENIED_OBJECT_ACE_TYPE
                | AceType::ACCESS_DENIED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            continue;
        }
        if !matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        ) {
            return Err(invalid("unsupported Windows private path ACE"));
        }
        let sid = ace.sid().ok_or_else(|| invalid("ACL entry has no SID"))?;
        if sid != current.as_ref()
            && !(matches!(allowed, AllowedPrincipals::OwnerSystemAdministrators)
                && matches!(sid.to_string().as_str(), "S-1-5-18" | "S-1-5-32-544"))
        {
            return Err(invalid("Windows private path permits a different user"));
        }
    }
    Ok(())
}

pub(super) fn set_file_acl(file: &mut fs::File, directory: bool) -> io::Result<()> {
    let current = current_process_sid()?;
    let descriptor = GetSecurityInfo(file, SE_FILE_OBJECT, SecurityInformation::Owner)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(invalid(
            "Windows private path owner is not the current Agent user",
        ));
    }
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{current})");
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse()?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("cannot create private Windows DACL"))?;
    SetSecurityInfo(
        file,
        SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
}

pub(super) fn reject_file_hardlinks(file: &fs::File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
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
