use super::*;

pub(super) fn replace_file(target: &Path, replacement: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = replacement
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: paths are NUL-terminated and zero flags require ACL preservation to succeed.
    if unsafe {
        ReplaceFileW(
            target.as_ptr(),
            replacement.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(super) fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > limit {
        return Err(invalid(
            "Agent enrollment file is unsafe or exceeds its size limit",
        ));
    }
    verify_private_acl(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("Agent enrollment file exceeds its size limit"));
    }
    Ok(bytes)
}
pub(super) fn canonical_private_dir(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(invalid(
            "Agent service directory must be a non-reparse directory",
        ));
    }
    verify_private_acl(path)?;
    let mut ancestor = path;
    while let Some(parent) = ancestor.parent() {
        let metadata = fs::symlink_metadata(parent)?;
        if is_reparse(&metadata) {
            return Err(invalid("Agent service path contains a reparse point"));
        }
        ancestor = parent;
    }
    path.canonicalize()
}
pub(super) fn verify_install_root(path: &Path) -> io::Result<PathBuf> {
    let root = canonical_private_dir(path)?;
    let local_app_data = local_app_data_path()?;
    let profile_metadata = fs::symlink_metadata(&local_app_data)?;
    if !profile_metadata.is_dir() || is_reparse(&profile_metadata) {
        return Err(invalid(
            "Windows LocalAppData profile boundary is missing or is a reparse point",
        ));
    }
    // SHGetKnownFolderPath is used instead of an environment variable, so a
    // caller cannot redirect lifecycle storage to a shared or spoofed tree.
    // The OS-owned profile directory is the trust boundary for ancestors.
    // The official installer uses LocalAppData/HostLink/Agent. Verify
    // every intermediate directory's private owner-only ACL rather than
    // rejecting the valid two-level layout or trusting shared parents.
    crate::private_fs::windows::validate_acl(
        &local_app_data,
        &profile_metadata,
        crate::private_fs::windows::AllowedPrincipals::OwnerSystemAdministrators,
        false,
    )?;
    // Canonicalize both sides: Windows typically returns a \\?\ path for
    // fs::canonicalize but SHGetKnownFolderPath yields an ordinary C:\ path.
    let profile = fs::canonicalize(&local_app_data)?;
    let relative = root.strip_prefix(&profile).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Agent root is outside the current user's Windows LocalAppData directory",
        )
    })?;
    let depth = relative.components().count();
    if depth == 0 || depth > 8 {
        return Err(invalid(
            "Agent root must be a bounded private descendant of LocalAppData",
        ));
    }
    let mut parent = root.parent();
    while let Some(directory) = parent {
        if directory == profile {
            break;
        }
        canonical_private_dir(directory)?;
        parent = directory.parent();
    }
    if parent != Some(profile.as_path()) {
        return Err(invalid("Agent root ancestry could not be verified"));
    }
    Ok(root)
}
pub(super) fn local_app_data_path() -> io::Result<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    // Win7 exposes SHGetFolderPathW from shell32.dll. The newer SDK's
    // CoTaskMemFree import may resolve to combase.dll, which is absent on
    // NT6.1 even when explicitly linked against its ole32 import library.
    // This older shell API maps CSIDL_LOCAL_APPDATA to the same known folder
    // on Vista+, and returns into a caller-owned buffer without COM memory.
    let mut buffer = [0u16; 260];
    // SAFETY: buffer has the MAX_PATH-wide-character capacity required by
    // SHGetFolderPathW; a null token selects the current process user.
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            CSIDL_LOCAL_APPDATA as i32,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(io::Error::other(format!(
            "cannot resolve the current user's Windows LocalAppData folder (HRESULT {result:#x})"
        )));
    }
    let length = buffer
        .iter()
        .position(|&unit| unit == 0)
        .filter(|&length| length > 0 && length < buffer.len() - 1)
        .ok_or_else(|| invalid("Windows LocalAppData path is empty or truncated"))?;
    PathBuf::from(OsString::from_wide(&buffer[..length])).canonicalize()
}
pub(super) fn canonical_regular(path: &Path) -> io::Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(invalid(
            "Agent service input must be a regular non-reparse file",
        ));
    }
    let file = File::open(path)?;
    let mut info = std::mem::MaybeUninit::<
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    >::uninit();
    // SAFETY: the open file handle is live and the API initializes the full output structure on success.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle().cast(),
            info.as_mut_ptr(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetFileInformationByHandle returned success and initialized `info`.
    if unsafe { info.assume_init() }.nNumberOfLinks != 1 {
        return Err(invalid("Agent service input must not have hard links"));
    }
    verify_private_acl(path)?;
    let mut ancestor = path.parent();
    while let Some(parent) = ancestor {
        let metadata = fs::symlink_metadata(parent)?;
        if is_reparse(&metadata) {
            return Err(invalid("Agent service input path contains a reparse point"));
        }
        ancestor = parent.parent();
    }
    path.canonicalize()
}
pub(super) fn verify_private_acl(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    crate::private_fs::windows::validate_acl(
        path,
        &metadata,
        crate::private_fs::windows::AllowedPrincipals::OwnerOnly,
        true,
    )
}
pub(super) fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & 0x400 != 0
}
pub(super) fn current_sid() -> io::Result<String> {
    Ok(windows_permissions::utilities::current_process_sid()
        .map_err(io::Error::other)?
        .to_string())
}
pub(super) fn ensure_user_scope() -> io::Result<()> {
    if crate::private_fs::windows::is_non_elevated_user()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Agent service management must run as a non-elevated current user",
        ))
    }
}
pub(super) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
pub(super) fn windows_quote(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push(ch);
            slashes = 0;
            continue;
        }
        out.push_str(&"\\".repeat(slashes));
        slashes = 0;
        out.push(ch);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path)?;
    let result = (|| {
        set_private_acl(path)?;
        verify_private_acl(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
pub(super) fn set_private_acl(path: &Path) -> io::Result<()> {
    crate::private_fs::windows::set_acl(path, false)
}
pub(super) fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub(super) fn random_token() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex(&bytes)
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn ssh_banner(addr: std::net::SocketAddr) -> io::Result<bool> {
    use std::net::TcpStream;
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(750)) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NotFound
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    stream.set_read_timeout(Some(Duration::from_millis(750)))?;
    let mut bytes = [0; 256];
    match stream.read(&mut bytes) {
        Ok(n) => Ok(String::from_utf8_lossy(&bytes[..n]).starts_with("SSH-2.0-")),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
