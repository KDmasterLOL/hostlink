use super::*;

pub(super) fn read_token(path: &Path) -> io::Result<SecretString> {
    durable::validate_private_path(path, false)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(invalid("enrollment token file exceeds size limit"));
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    let token =
        String::from_utf8(bytes).map_err(|_| invalid("enrollment token file is not UTF-8"))?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("enrollment token file has invalid format"));
    }
    Ok(SecretString::from(token))
}

pub(super) fn public_key(key: &PrivateKey) -> io::Result<String> {
    let mut public = key.public_key().clone();
    public.set_comment(String::new());
    public.to_openssh().map_err(io::Error::other)
}

pub(super) fn write_private_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot create private enrollment file {}: {error}",
                path.display()
            ),
        )
    })?;
    durable::restrict_private_path(path, false).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "private enrollment file validation failed for {}: {error}",
                path.display()
            ),
        )
    })?;
    file.write_all(contents)?;
    file.sync_all()
}

pub(super) fn ensure_fresh_root_parent(root: &Path) -> io::Result<()> {
    if root.exists() || fs::symlink_metadata(root).is_ok() {
        return Err(invalid(
            "Agent install root already exists; enrollment never adopts an existing root",
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| invalid("Agent install root has no parent"))?;
    #[cfg(not(windows))]
    {
        let canonical = fs::canonicalize(parent)?;
        if canonical != parent {
            return Err(invalid(
                "Agent install root parent path contains a symlink or traversal alias",
            ));
        }
    }
    // On Windows canonicalize() rewrites ordinary C:\ paths into \\?\C:\
    // extended-length paths. Their PathBuf values differ even in the absence
    // of a junction. Inspect each ancestor without following reparse points
    // rather than treating that benign prefix conversion as an alias.
    #[cfg(windows)]
    reject_windows_parent_reparse_components(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("Agent install root parent is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads the current process identity and has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent install root parent is not user-owned",
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent install root parent is writable by another user",
            ));
        }
    }
    #[cfg(windows)]
    durable::validate_private_path(parent, true)?;
    Ok(())
}

pub(super) fn local_hostname() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .unwrap_or_else(|| "unknown-host".into())
}

pub(super) fn available_loopback_addr() -> io::Result<SocketAddr> {
    available_loopback_addr_from(std::iter::repeat_with(|| {
        rng().random_range(AGENT_LISTENER_PORTS.clone())
    }))
}

pub(super) fn available_loopback_addr_from(
    candidates: impl Iterator<Item = u16>,
) -> io::Result<SocketAddr> {
    for port in candidates.take(LISTENER_PORT_ATTEMPTS) {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        match TcpListener::bind(address) {
            Ok(listener) => {
                let address = listener.local_addr()?;
                // Enrollment publishes the address before a separate Agent process starts.
                // Releasing this probe leaves an unavoidable TOCTOU window in which another
                // process can claim the port; Agent startup still fails closed if that happens.
                drop(listener);
                return Ok(address);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "could not find an available loopback port in {}-{} after {} attempts; retry enrollment",
            AGENT_LISTENER_PORTS.start(),
            AGENT_LISTENER_PORTS.end(),
            LISTENER_PORT_ATTEMPTS
        ),
    ))
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
