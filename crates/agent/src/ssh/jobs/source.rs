use super::*;

/// Verifies the immutable source and platform launch context before process creation.
pub(in crate::ssh) fn verify_job_source(spec: &JobSpec) -> io::Result<PathBuf> {
    if !Path::new(&spec.program).is_absolute() || spec.program.contains('\0') {
        return Err(invalid_data("job executable must be an absolute path"));
    }
    let program = Path::new(&spec.program);
    let metadata = std::fs::symlink_metadata(program)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            "job executable must be a regular non-symlink file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid_data("job executable must not be a reparse point"));
        }
        if !crate::exec::safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable jobs require a verified non-elevated, non-LocalSystem Windows user context",
            ));
        }
        durable::validate_private_path(program, false)?;
        if let Some(parent) = program.parent() {
            durable::validate_private_path(parent, true)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid_data("job executable has no execute permission"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(program)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(invalid_data("job executable must be a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_size() != opened_metadata.file_size()
            || metadata.last_write_time() != opened_metadata.last_write_time()
            || metadata.creation_time() != opened_metadata.creation_time()
        {
            return Err(invalid_data(
                "job executable path changed while opening for verification",
            ));
        }
    }
    #[cfg(windows)]
    let original_identity = windows_file_identity(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened_metadata.uid() != unsafe { libc::geteuid() }
            || opened_metadata.nlink() != 1
            || opened_metadata.permissions().mode() & 0o222 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job executable must be Agent-owned, singly linked and read-only",
            ));
        }
    }
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest_writer(&mut digest))?;
    if format!("{:x}", digest.finalize()) != spec.source_sha256 {
        return Err(invalid_data("job executable digest mismatch"));
    }
    let after_hash = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if after_hash.dev() != opened_metadata.dev()
            || after_hash.ino() != opened_metadata.ino()
            || after_hash.len() != opened_metadata.len()
            || after_hash.mtime() != opened_metadata.mtime()
            || after_hash.mtime_nsec() != opened_metadata.mtime_nsec()
            || after_hash.ctime() != opened_metadata.ctime()
            || after_hash.ctime_nsec() != opened_metadata.ctime_nsec()
            || path_after_hash.file_type().is_symlink()
            || path_after_hash.dev() != opened_metadata.dev()
            || path_after_hash.ino() != opened_metadata.ino()
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if path_after_hash.file_attributes() & 0x400 != 0
            || after_hash.file_size() != opened_metadata.file_size()
            || after_hash.last_write_time() != opened_metadata.last_write_time()
            || path_after_hash.file_size() != opened_metadata.file_size()
            || path_after_hash.last_write_time() != opened_metadata.last_write_time()
            || original_identity != windows_file_identity(&file)?
            || original_identity != windows_file_identity(&std::fs::File::open(program)?)?
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    // The open descriptor is hashed, then ProcessKit launches by pathname. Read-only ownership
    // checks reduce external mutation, but cannot pin the executed inode against a same-UID path
    // replacement between this check and exec; this is not an exec-by-fd guarantee.
    if let Some(cwd) = &spec.cwd {
        let metadata = std::fs::symlink_metadata(cwd)?;
        if !cwd.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid_data(
                "job working directory must be absolute and safe",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid_data("job working directory is a reparse point"));
            }
            durable::validate_private_path(cwd, true)?;
        }
    }
    Ok(program.to_path_buf())
}

/// Stable Win32 replacement for nightly-only MetadataExt file_index and
/// volume_serial_number. GetFileInformationByHandle is present on NT6.1.
#[cfg(windows)]
fn windows_file_identity(file: &std::fs::File) -> io::Result<(u32, u64, u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is an open, owned File handle, and info points to a
    // correctly sized writable Win32 output structure.
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    let write_time = (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
        | u64::from(info.ftLastWriteTime.dwLowDateTime);
    // Ambiguous file identity or multiple hardlinks cannot establish
    // that this source is the single privately controlled executable.
    if index == 0 || info.nNumberOfLinks != 1 {
        return Err(invalid_data(
            "source-pinned Windows executable identity is ambiguous or multiply linked",
        ));
    }
    Ok((info.dwVolumeSerialNumber, index, size, write_time))
}

fn digest_writer<'a>(digest: &'a mut Sha256) -> impl io::Write + 'a {
    struct DigestWriter<'a>(&'a mut Sha256);
    impl io::Write for DigestWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    DigestWriter(digest)
}
