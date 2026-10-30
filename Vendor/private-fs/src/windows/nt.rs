//! Single-component NT opens and handle-bound object metadata.
#![allow(unsafe_code)]
use super::{
    bindings::*,
    security::{self, Descriptor, Sid},
};
use crate::{Error, Result};
use std::{
    ffi::OsStr,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};

// Pure identity policy is kept separate from the native queries for testing.
pub(super) mod identity {
    use super::super::bindings::*;
    use crate::{Error, Result};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in super::super) enum Identity {
        Legacy { volume: u32, id: u64 },
        Extended { volume: u64, id: [u8; 16] },
    }

    impl Identity {
        pub(in super::super) fn legacy(value: &BY_HANDLE_FILE_INFORMATION) -> Self {
            Self::Legacy {
                volume: value.dwVolumeSerialNumber,
                id: (u64::from(value.nFileIndexHigh) << 32) | u64::from(value.nFileIndexLow),
            }
        }
    }

    pub(in super::super) fn unsupported_class(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION)
        )
    }

    pub(in super::super) fn legacy_volume(
        filesystem: &[u16],
        device: &FILE_FS_DEVICE_INFORMATION,
        flags: u32,
    ) -> Result<()> {
        volume_flags(flags)?;
        // ReFS needs all 128 bits; remote NTFS cannot supply local identity guarantees.
        local_disk(device)?;
        if filesystem != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16] {
            return Err(Error::UnsupportedFilesystem {
                capability: "local NTFS file identity on legacy Windows",
            });
        }
        Ok(())
    }

    pub(in super::super) fn local_disk(device: &FILE_FS_DEVICE_INFORMATION) -> Result<()> {
        if device.DeviceType != FILE_DEVICE_DISK || device.Characteristics & FILE_REMOTE_DEVICE != 0
        {
            return Err(Error::UnsupportedFilesystem {
                capability: "local Windows disk device",
            });
        }
        Ok(())
    }

    pub(in super::super) fn volume_flags(flags: u32) -> Result<()> {
        if flags & FILE_PERSISTENT_ACLS as u32 == 0 {
            return Err(Error::UnsupportedFilesystem {
                capability: "persistent Windows ACLs",
            });
        }
        Ok(())
    }
}
pub(super) use identity::{Identity, volume_flags};

pub(super) mod open_policy {
    use super::super::bindings::*;
    use crate::{Error, Result};

    pub(in super::super) fn unsupported_flag(status: NTSTATUS) -> bool {
        matches!(status, STATUS_INVALID_PARAMETER | STATUS_INVALID_INFO_CLASS)
    }

    pub(in super::super) fn component(name: &[u16]) -> Result<()> {
        const FORBIDDEN: [u16; 4] = [0, b'/' as u16, b':' as u16, b'\\' as u16];
        if name.is_empty()
            || name == [b'.' as u16]
            || name == [b'.' as u16, b'.' as u16]
            || name.iter().any(|unit| FORBIDDEN.contains(unit))
        {
            return Err(Error::InvalidRelativePath);
        }
        Ok(())
    }

    pub(in super::super) fn drive_anchor(name: &[u16]) -> Result<[u16; 3]> {
        if name.len() != 7
            || name[..4] != (*b"\\??\\").map(u16::from)
            || name[5..] != (*b":\\").map(u16::from)
            || !u8::try_from(name[4]).is_ok_and(|letter| letter.is_ascii_alphabetic())
        {
            return Err(Error::InvalidRelativePath);
        }
        Ok([name[4], b':' as u16, 0])
    }

    pub(in super::super) fn volume_root(target: &[u16]) -> Result<Vec<u16>> {
        let prefix: Vec<_> = r"\Device\HarddiskVolume".encode_utf16().collect();
        let Some(number) = target.strip_prefix(prefix.as_slice()) else {
            return Err(Error::InvalidRelativePath);
        };
        if number.is_empty()
            || !number
                .iter()
                .all(|&unit| u8::try_from(unit).is_ok_and(|byte| byte.is_ascii_digit()))
        {
            return Err(Error::InvalidRelativePath);
        }
        let mut root = target.to_vec();
        root.push(b'\\' as u16);
        Ok(root)
    }
}

#[cfg(test)]
std::thread_local! {
    pub(super) static FORCE_LEGACY_IDENTITY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FORCE_OPEN_STATUS: std::cell::Cell<Option<NTSTATUS>> = const { std::cell::Cell::new(None) };
}

fn identity(handle: impl AsHandle) -> Result<Identity> {
    #[cfg(not(test))]
    let value = info::<FILE_ID_INFO>(handle.as_handle(), FileIdInfo);
    #[cfg(test)]
    let value = if FORCE_LEGACY_IDENTITY.get() {
        // Simulate only the unavailable class; the fallback uses real Win32 calls.
        Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER).into())
    } else {
        info::<FILE_ID_INFO>(handle.as_handle(), FileIdInfo)
    };
    match value {
        Ok(value) => Ok(Identity::Extended {
            volume: value.VolumeSerialNumber,
            id: value.FileId.Identifier,
        }),
        Err(Error::Io(error)) if identity::unsupported_class(&error) => legacy_identity(handle),
        Err(error) => Err(error),
    }
}

fn legacy_identity(handle: impl AsHandle) -> Result<Identity> {
    let mut flags = 0;
    let mut filesystem = [0u16; 261];
    // SAFETY: live handle and writable scalar/UTF-16 outputs of the stated sizes.
    security::bool_result(unsafe {
        GetVolumeInformationByHandleW(
            handle.as_handle().as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    })?;
    let device = device_information(handle.as_handle())?;
    let end = filesystem
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(filesystem.len());
    identity::legacy_volume(&filesystem[..end], &device, flags)?;
    let mut value = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live handle and exact initialized Win32 output structure.
    security::bool_result(unsafe {
        GetFileInformationByHandle(handle.as_handle().as_raw_handle(), &mut value)
    })?;
    Ok(Identity::legacy(&value))
}

fn device_information(handle: impl AsHandle) -> Result<FILE_FS_DEVICE_INFORMATION> {
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: FileFsDeviceInformation queries the device associated with this
    // retained handle, with an exactly sized/aligned output and live status block.
    nt_result(unsafe {
        NtQueryVolumeInformationFile(
            handle.as_handle().as_raw_handle(),
            &mut status,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    })?;
    if status.Information != size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(Error::UnsupportedFilesystem {
            capability: "Windows volume device information",
        });
    }
    Ok(device)
}

fn resolve_drive_anchor(name: &[u16]) -> Result<Vec<u16>> {
    let drive = open_policy::drive_anchor(name)?;
    let mut target = [0u16; 1024];
    // SAFETY: NUL-terminated drive name and a writable, bounded UTF-16 MULTI_SZ.
    let length =
        unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    if length == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let data = target
        .get(..length as usize)
        .ok_or(Error::InvalidRelativePath)?;
    // The first mapping is current; subsequent entries can be stale mappings.
    let end = data
        .iter()
        .position(|&unit| unit == 0)
        .ok_or(Error::InvalidRelativePath)?;
    open_policy::volume_root(&data[..end])
}

pub(super) fn open(
    parent: Option<&OwnedHandle>,
    name: &OsStr,
    directory: bool,
    disposition: u32,
    user: Option<&Sid>,
) -> Result<OwnedHandle> {
    open_access(parent, name, directory, disposition, user, None)
}
pub(super) fn open_file(
    parent: &OwnedHandle,
    name: &OsStr,
    disposition: u32,
    user: Option<&Sid>,
    writable: bool,
    deleting: bool,
) -> Result<OwnedHandle> {
    let access = (FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) as u32
        | if writable { FILE_WRITE_DATA as u32 } else { 0 }
        | if deleting || disposition != FILE_OPEN as u32 {
            DELETE as u32
        } else {
            0
        };
    open_access(Some(parent), name, false, disposition, user, Some(access))
}
fn open_access(
    parent: Option<&OwnedHandle>,
    name: &OsStr,
    directory: bool,
    disposition: u32,
    user: Option<&Sid>,
    desired_override: Option<u32>,
) -> Result<OwnedHandle> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    if ![FILE_OPEN as u32, FILE_CREATE as u32, FILE_OPEN_IF as u32].contains(&disposition)
        || name.len() > (u16::MAX as usize) / 2
    {
        return Err(Error::InvalidRelativePath);
    }
    let anchor = parent.is_none();
    if anchor {
        if !directory
            || disposition != FILE_OPEN as u32
            || user.is_some()
            || desired_override.is_some()
        {
            return Err(Error::InvalidRelativePath);
        }
        // Resolve the DOS alias once. Only a trusted OS device root is opened;
        // never retry an arbitrary absolute pathname or re-resolve the drive alias.
        name = resolve_drive_anchor(&name)?;
    } else if !name.is_empty() {
        open_policy::component(&name)?;
    } else if desired_override.is_none() || disposition != FILE_OPEN as u32 || user.is_some() {
        return Err(Error::InvalidRelativePath);
    }
    let bytes = (name.len() * 2) as u16;
    let mut string = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let mut security = user.map(Descriptor::new).transpose()?;
    let mut attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.map_or(ptr::null_mut(), |p| p.as_raw_handle()),
        ObjectName: &mut string,
        // OBJ_INHERIT is deliberately absent at the original creation call.
        Attributes: (OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE) as u32,
        SecurityDescriptor: security
            .as_mut()
            .map_or(ptr::null_mut(), Descriptor::as_ptr),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let creating = disposition != FILE_OPEN as u32;
    let desired = if creating {
        FILE_ALL_ACCESS as u32
    } else {
        (FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) as u32
            | if directory {
                FILE_LIST_DIRECTORY as u32
            } else {
                FILE_READ_DATA as u32
            }
    };
    let desired = desired_override.unwrap_or(desired);
    let mut handle = ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    // Existing entries are opened type-neutral and inspected before use. New
    // entries must have the intended kind as part of their creation syscall.
    let options = FILE_OPEN_REPARSE_POINT as u32
        | if desired & SYNCHRONIZE as u32 != 0 {
            FILE_SYNCHRONOUS_IO_NONALERT as u32
        } else {
            0
        }
        | if creating {
            if directory {
                FILE_DIRECTORY_FILE as u32
            } else {
                FILE_NON_DIRECTORY_FILE as u32
            }
        } else {
            0
        };
    let mut create = |attributes: &OBJECT_ATTRIBUTES, desired| {
        // SAFETY: all names, outputs, and optional protected descriptor stay live
        // across both attempts. Neither attempt uses overwrite/delete-on-close.
        unsafe {
            NtCreateFile(
                &mut handle,
                desired,
                attributes,
                &mut io_status,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL as u32,
                (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u32,
                disposition,
                options,
                ptr::null(),
                0,
            )
        }
    };
    #[cfg(not(test))]
    let mut status = create(&attributes, desired);
    #[cfg(test)]
    let mut status = FORCE_OPEN_STATUS
        .get()
        .unwrap_or_else(|| create(&attributes, desired));
    let retried = open_policy::unsupported_flag(status);
    if retried {
        attributes.Attributes &= !(OBJ_DONT_REPARSE as u32);
        // FILE_OPEN_REPARSE_POINT is retained. Attribute access is mandatory for
        // inspecting the acquired handle before it can escape, including reopens.
        status = create(&attributes, desired | FILE_READ_ATTRIBUTES as u32);
    }
    if status < 0 {
        if status == STATUS_REPARSE_POINT_ENCOUNTERED || status == STATUS_STOPPED_ON_SYMLINK {
            return Err(Error::PathRedirect);
        }
        // SAFETY: scalar NTSTATUS conversion does not dereference pointers.
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    // SAFETY: successful NtCreateFile transferred a unique non-inheritable handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    if retried || desired & FILE_READ_ATTRIBUTES as u32 != 0 {
        let directory = if retried && name.is_empty() && desired & FILE_READ_ATTRIBUTES as u32 == 0
        {
            // Security-only empty-name reopens can refer to a file or directory.
            let standard: FILE_STANDARD_INFO =
                info(parent.ok_or(Error::InvalidRelativePath)?, FileStandardInfo)?;
            standard.Directory
        } else {
            directory
        };
        kind(&handle, directory)?;
    }
    if anchor {
        identity::local_disk(&device_information(&handle)?)?;
        volume(&handle)?;
    }
    Ok(handle)
}
fn info<T: Default>(handle: impl AsHandle, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T> {
    let mut value = T::default();
    // SAFETY: internal callers match the class to its exact output structure.
    security::bool_result(unsafe {
        GetFileInformationByHandleEx(
            handle.as_handle().as_raw_handle(),
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        )
    })?;
    Ok(value)
}
pub(super) fn kind(handle: impl AsHandle, directory: bool) -> Result<()> {
    // SAFETY: live borrowed handle; GetFileType has no output pointer.
    if unsafe { GetFileType(handle.as_handle().as_raw_handle()) } != FILE_TYPE_DISK as u32 {
        return Err(Error::WrongObjectKind);
    }
    let attributes: FILE_ATTRIBUTE_TAG_INFO = info(handle.as_handle(), FileAttributeTagInfo)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT as u32 != 0 {
        return Err(Error::PathRedirect);
    }
    if (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY as u32 != 0) != directory {
        return Err(Error::WrongObjectKind);
    }
    Ok(())
}
pub(super) fn volume(handle: impl AsHandle) -> Result<()> {
    let mut flags = 0;
    // SAFETY: optional buffers are null/zero; flags is a writable u32 output.
    security::bool_result(unsafe {
        GetVolumeInformationByHandleW(
            handle.as_handle().as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            ptr::null_mut(),
            0,
        )
    })?;
    volume_flags(flags)
}
pub(super) fn metadata(
    handle: impl AsHandle,
    directory: bool,
    expected: Option<Identity>,
) -> Result<Identity> {
    kind(handle.as_handle(), directory)?;
    volume(handle.as_handle())?;
    let id = identity(handle.as_handle())?;
    if expected.is_some_and(|expected| expected != id) {
        return Err(Error::IdentityChanged);
    }
    let standard: FILE_STANDARD_INFO = info(handle.as_handle(), FileStandardInfo)?;
    if standard.Directory != directory || standard.DeletePending {
        return Err(Error::WrongObjectKind);
    }
    if !directory && standard.NumberOfLinks != 1 {
        return Err(Error::MultipleHardLinks {
            links: u64::from(standard.NumberOfLinks),
        });
    }
    Ok(id)
}
pub(super) fn validate(
    handle: impl AsHandle,
    directory: bool,
    expected: Option<Identity>,
    user: &Sid,
) -> Result<Identity> {
    let id = metadata(handle.as_handle(), directory, expected)?;
    security::verify(handle, user)?;
    Ok(id)
}

pub(super) fn flush(handle: impl AsHandle) -> Result<()> {
    // SAFETY: live borrowed handle; the call is synchronous and has no outputs.
    security::bool_result(unsafe { FlushFileBuffers(handle.as_handle().as_raw_handle()) })
}

pub(super) fn directory_for_sync(parent: &OwnedHandle) -> Result<OwnedHandle> {
    open_access(
        Some(parent),
        OsStr::new(""),
        true,
        FILE_OPEN as u32,
        None,
        Some((FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE) as u32),
    )
}

pub(super) fn rename_with_policy(
    file: impl AsHandle,
    parent: &OwnedHandle,
    target: &OsStr,
    policy: crate::Publication,
) -> Result<()> {
    rename_impl(
        file,
        parent,
        target,
        false,
        policy == crate::Publication::Replace,
    )
}
#[cfg(test)]
pub(super) fn rename_classic(
    file: impl AsHandle,
    parent: &OwnedHandle,
    target: &OsStr,
) -> Result<()> {
    rename_impl(file, parent, target, true, true)
}
fn rename_impl(
    file: impl AsHandle,
    parent: &OwnedHandle,
    target: &OsStr,
    force_classic: bool,
    replace: bool,
) -> Result<()> {
    let name: Vec<u16> = target.encode_wide().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let bytes = (offset + name.len() * 2).max(size_of::<FILE_RENAME_INFORMATION>());
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: pointer-aligned initialized allocation covers the fixed structure
    // and UTF-16 tail. RootDirectory pins the destination; source is the live
    // file handle. No complete pathname or mutable source name is reopened.
    unsafe {
        (*rename).Anonymous.Flags = FILE_RENAME_POSIX_SEMANTICS as u32
            | if replace {
                FILE_RENAME_REPLACE_IF_EXISTS as u32
            } else {
                0
            };
        (*rename).RootDirectory = parent.as_raw_handle();
        (*rename).FileNameLength = (name.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            storage.as_mut_ptr().cast::<u8>().add(offset).cast(),
            name.len(),
        );
        let mut status = IO_STATUS_BLOCK::default();
        let result = if force_classic {
            // Test-only callers simulate an unavailable extended class; execute
            // the real classic syscall with the same source and parent handles.
            STATUS_INVALID_INFO_CLASS
        } else {
            NtSetInformationFile(
                file.as_handle().as_raw_handle(),
                &mut status,
                rename.cast(),
                bytes as u32,
                FileRenameInformationEx,
            )
        };
        if matches!(
            result,
            STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_INVALID_PARAMETER
        ) {
            // Older kernels/filesystems retain classic atomic rename semantics,
            // but can refuse open destinations. Never emulate replacement by unlink.
            (*rename).Anonymous.Flags = 0;
            (*rename).Anonymous.ReplaceIfExists = replace;
            return nt_result(NtSetInformationFile(
                file.as_handle().as_raw_handle(),
                &mut status,
                rename.cast(),
                bytes as u32,
                FileRenameInformation,
            ));
        }
        nt_result(result)
    }
}
pub(super) fn delete(file: impl AsHandle) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: live DELETE-capable file handle and matching initialized payload.
    // The OS marks this exact opened object for removal when its handles close.
    security::bool_result(unsafe {
        SetFileInformationByHandle(
            file.as_handle().as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    })
}

fn nt_result(status: NTSTATUS) -> Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: scalar status conversion only.
    Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into())
}
pub(super) fn identity_matches(handle: impl AsHandle, expected: Identity) -> Result<()> {
    if identity(handle)? != expected {
        return Err(Error::IdentityChanged);
    }
    Ok(())
}
pub(super) fn security_handle(handle: impl AsHandle) -> Result<OwnedHandle> {
    let owned = handle.as_handle().try_clone_to_owned()?;
    open_access(
        Some(&owned),
        OsStr::new(""),
        false,
        FILE_OPEN as u32,
        None,
        Some((READ_CONTROL | WRITE_DAC) as u32),
    )
}

pub(super) fn directory_for_listing(parent: &OwnedHandle) -> Result<OwnedHandle> {
    open_access(
        Some(parent),
        OsStr::new(""),
        true,
        FILE_OPEN as u32,
        None,
        Some((FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) as u32),
    )
}
pub(super) fn entries(handle: impl AsHandle) -> Result<Vec<std::ffi::OsString>> {
    use std::os::windows::ffi::OsStringExt;
    let mut storage = vec![0u64; 65536 / size_of::<u64>()];
    let bytes = storage.len() * size_of::<u64>();
    let mut class = FileIdBothDirectoryRestartInfo;
    let mut names = Vec::new();
    loop {
        storage.fill(0);
        // SAFETY: pointer-aligned storage covers the directory information buffer.
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle.as_handle().as_raw_handle(),
                class,
                storage.as_mut_ptr().cast(),
                bytes as u32,
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES) {
                break;
            }
            return Err(error.into());
        }
        class = FileIdBothDirectoryInfo;
        let mut offset = 0usize;
        loop {
            let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if !offset.is_multiple_of(std::mem::align_of::<FILE_ID_BOTH_DIR_INFO>())
                || bytes - offset < size_of::<FILE_ID_BOTH_DIR_INFO>()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed directory record",
                )
                .into());
            }
            // SAFETY: aligned record header and filename range are bounded before reads.
            let (name, next) = unsafe {
                let record = &*storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>();
                let length = record.FileNameLength as usize;
                let next = record.NextEntryOffset as usize;
                let record_bytes = if next == 0 { bytes - offset } else { next };
                if !length.is_multiple_of(2)
                    || record_bytes < name_offset
                    || record_bytes > bytes - offset
                    || length > record_bytes - name_offset
                    || (next != 0 && next < size_of::<FILE_ID_BOTH_DIR_INFO>())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed directory name",
                    )
                    .into());
                }
                let units = std::slice::from_raw_parts(
                    storage
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset + name_offset)
                        .cast::<u16>(),
                    length / 2,
                );
                (std::ffi::OsString::from_wide(units), next)
            };
            if name != OsStr::new(".") && name != OsStr::new("..") {
                crate::path::RelativePath::new(std::path::Path::new(&name))?;
                names.push(name);
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
    Ok(names)
}
