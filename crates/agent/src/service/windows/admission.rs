use super::*;

pub(super) fn consume_maintenance_admission(record: &InstallRecord) -> io::Result<()> {
    let mut capability = [0u8; 128];
    read_private_child_capability(&mut capability)?;
    if !capability.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("maintenance candidate capability is malformed"));
    }

    let path = record.root.join(MAINTENANCE_ADMISSION);
    let mut file = open_maintenance_admission(&path)?;
    let metadata = file.metadata()?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((MAX_MAINTENANCE_ADMISSION + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MAINTENANCE_ADMISSION {
        return Err(invalid("maintenance admission file exceeds size limit"));
    }
    let admission: MaintenanceAdmission = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("maintenance admission file is malformed"))?;
    if !admission_matches(
        &admission,
        record,
        std::str::from_utf8(&capability)
            .map_err(|_| invalid("maintenance capability is not UTF-8"))?,
    ) || registry_value(&record.run_value)?.is_some()
        || std::env::current_exe()?.canonicalize()? != record.executable
        || sha256_file(&record.executable)? != admission.executable_sha256
    {
        return Err(invalid(
            "maintenance candidate admission identity does not match",
        ));
    }

    // The open handle denies all competing reads. Delete while holding it so exactly one
    // claimant can consume this ticket; a failed identity check leaves it available for recovery.
    fs::remove_file(&path)?;
    Ok(())
}
pub(super) fn open_maintenance_admission(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    fs::symlink_metadata(path)?;
    verify_private_acl(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(0x00000004) // FILE_SHARE_DELETE only; serializes claimants.
        .custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT.
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || is_reparse(&metadata)
        || metadata.len() > MAX_MAINTENANCE_ADMISSION as u64
    {
        return Err(invalid("maintenance admission file is unsafe or oversized"));
    }
    Ok(file)
}
/// Create an admission record without replacing existing state, and report cleanup
/// failures if ACL setup or the durable write fails after the file was created.
pub(super) fn write_maintenance_admission(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = (|| {
        set_private_acl(path)?;
        verify_private_acl(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    drop(file);
    match result {
        Ok(()) => Ok(()),
        Err(write_error) => match fs::remove_file(path) {
            Ok(()) => Err(write_error),
            Err(remove_error) if remove_error.kind() == io::ErrorKind::NotFound => Err(write_error),
            Err(remove_error) => Err(io::Error::other(format!(
                "maintenance admission write failed ({write_error}); partial record cleanup failed: {remove_error}"
            ))),
        },
    }
}
/// Remove only the record this coordinator issued. If the path now names different or
/// unsafe state, preserve it and return an error for the caller's rollback path.
pub(super) fn remove_maintenance_admission(path: &Path, expected: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    if let Err(error) = verify_private_acl(path) {
        return if matches!(fs::symlink_metadata(path), Err(ref missing) if missing.kind() == io::ErrorKind::NotFound)
        {
            Ok(())
        } else {
            Err(error)
        };
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(0x00000004) // FILE_SHARE_DELETE only; serializes claimants.
        .custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT.
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || is_reparse(&metadata)
        || metadata.len() > MAX_MAINTENANCE_ADMISSION as u64
    {
        return Err(invalid("maintenance admission cleanup found unsafe state"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((MAX_MAINTENANCE_ADMISSION + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(invalid(
            "maintenance admission cleanup found a different record; state preserved",
        ));
    }
    fs::remove_file(path)
}
pub(super) fn admission_matches(
    admission: &MaintenanceAdmission,
    record: &InstallRecord,
    capability: &str,
) -> bool {
    admission.format == 1
        && admission.transaction_id.len() == 64
        && admission
            .transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && capability.len() == 128
        && capability[..64] == admission.transaction_id
        && admission.root == record.root
        && admission.owner_sid == record.owner_sid
        && admission.executable_sha256 == record.executable_sha256
        && admission.capability_sha256
            == format!("{:x}", Sha256::digest(&capability.as_bytes()[64..]))
        && record.maintenance
        && record.maintenance_previous_sha256.is_some()
}
pub(super) fn read_private_child_capability(capability: &mut [u8; 128]) -> io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: i32) -> *mut std::ffi::c_void;
        fn PeekNamedPipe(
            pipe: *mut std::ffi::c_void,
            buffer: *mut std::ffi::c_void,
            buffer_size: u32,
            bytes_read: *mut u32,
            total_bytes_available: *mut u32,
            bytes_left_this_message: *mut u32,
        ) -> i32;
    }
    // SAFETY: -10 is the documented STD_INPUT_HANDLE selector and the call reads no pointers.
    let handle = unsafe { GetStdHandle(-10) };
    if handle.is_null() {
        return Err(invalid(
            "maintenance candidate has no inherited capability pipe",
        ));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut available = 0u32;
        // SAFETY: only the byte-count output is used; the supplied pipe handle is inherited stdin.
        let peeked = unsafe {
            PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if peeked == 0 {
            return Err(invalid("maintenance candidate stdin is not a private pipe"));
        }
        if available >= capability.len() as u32 {
            return io::stdin().read_exact(capability);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "maintenance candidate capability was not supplied",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
