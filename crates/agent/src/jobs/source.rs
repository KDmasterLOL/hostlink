use super::*;

/// Execute only the current controller's sealed artifact. The managed
/// directory and file are private; no second host-wide filesystem policy.
pub(super) fn verify_job_source(
    store: &JobStore,
    owner: &str,
    spec: &JobSpec,
) -> io::Result<PathBuf> {
    let program = Path::new(&spec.program);
    if !program.is_absolute() || spec.program.contains('\0') {
        return Err(invalid_data("job executable must be an absolute path"));
    }
    // Also enforces the exact canonical per-controller sealed filename,
    // private owner/ACL and non-symlink regular-file requirements.
    store
        .artifacts(owner)?
        .authorize_source(&spec.program, &spec.source_sha256)?;
    let metadata = fs::symlink_metadata(program)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 || !crate::exec::safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job executable requires a safe Windows user context and no reparse point",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 || metadata.permissions().mode() & 0o222 != 0
        {
            return Err(invalid_data(
                "sealed executable must be executable and read-only",
            ));
        }
    }

    // The artifact was SHA-verified when sealed. Recheck once at dequeue: it
    // may have changed while queued. Like ProcessKit, launch is path-based,
    // not an atomic exec-by-file-descriptor guarantee against this user.
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(program)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    if format!("{:x}", hasher.finalize()) != spec.source_sha256 {
        return Err(invalid_data("job executable digest mismatch"));
    }

    if let Some(cwd) = &spec.cwd {
        let metadata = fs::symlink_metadata(cwd)?;
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
            validate_private_path(cwd, true)?;
        }
    }
    Ok(program.to_path_buf())
}
