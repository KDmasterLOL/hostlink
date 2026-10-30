use super::*;

pub(super) fn read_token(path: &Path) -> io::Result<SecretString> {
    // Resolve relative names lexically before selecting the capability root.
    // The file is still opened nofollow via the same checked handle.
    let absolute = std::path::absolute(path)?;
    let mut bytes = Vec::new();
    PrivateDir::open(
        absolute
            .parent()
            .ok_or_else(|| invalid("token has no parent"))?,
    )
    .map_err(io::Error::other)?
    .open_file(
        absolute
            .file_name()
            .ok_or_else(|| invalid("token has no name"))?,
    )
    .map_err(io::Error::other)?
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
    let parent = path
        .parent()
        .ok_or_else(|| invalid("private file has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("private file has no name"))?;
    let mut file = PrivateDir::open(parent)
        .map_err(io::Error::other)?
        .create(name)
        .map_err(io::Error::other)?;
    file.write_all(contents)?;
    file.sync_all().map_err(io::Error::other)
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    PrivateDir::open(path)
        .map_err(io::Error::other)?
        .sync_all()
        .map_err(io::Error::other)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn ensure_fresh_root_parent(root: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        if !matches!(
            root.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            return Err(invalid(
                "Agent install root must be on a local Windows drive",
            ));
        }
    }
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
    #[cfg(windows)]
    PrivateDir::open(parent).map_err(io::Error::other)?;
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
