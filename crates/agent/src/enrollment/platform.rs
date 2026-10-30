use super::*;

pub(super) fn reject_elevated_user() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "enrollment must run as a normal user",
            ));
        }
    }
    #[cfg(windows)]
    if !crate::private_fs::windows::is_non_elevated_user()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "enrollment must not run elevated or as SYSTEM",
        ));
    }
    Ok(())
}
