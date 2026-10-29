#![allow(unused_imports)]
use super::*;

pub(crate) struct PreparedEmbeddedSshConfig {
    pub(super) expected_user: Arc<str>,
    pub(super) host_key: PrivateKey,
    pub(super) authorized_keys: Arc<Vec<PublicKey>>,
}

fn load_host_key(path: &Path) -> io::Result<PrivateKey> {
    load_private_ed25519_key(path, "embedded SSH host key")
}

fn load_private_ed25519_key(path: &Path, purpose: &str) -> io::Result<PrivateKey> {
    let bytes = read_bounded(path, HOST_KEY_MAX_BYTES)?;
    let key = PrivateKey::from_openssh(&bytes)
        .map_err(|error| invalid_data(format!("invalid {purpose}: {error}")))?;
    if key.is_encrypted() {
        return Err(invalid_data(format!(
            "{purpose} must be unencrypted for unattended agent startup"
        )));
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid_data(format!(
            "{purpose} must be Ed25519, got {}",
            key.algorithm()
        )));
    }
    Ok(key)
}

fn load_authorized_keys(path: &Path) -> io::Result<Vec<PublicKey>> {
    let bytes = read_bounded(path, AUTHORIZED_KEYS_MAX_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        invalid_data(format!("authorized controller keys are not UTF-8: {error}"))
    })?;
    let mut keys = Vec::new();

    for entry in AuthorizedKeys::new(text) {
        let entry = entry
            .map_err(|error| invalid_data(format!("invalid authorized controller key: {error}")))?;
        if !entry.config_opts().is_empty() {
            return Err(invalid_data(
                "embedded SSH authorized controller keys must not use sshd-specific options",
            ));
        }
        let key = entry.public_key();
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(invalid_data(format!(
                "embedded SSH authorized controller key must be Ed25519, got {}",
                key.algorithm()
            )));
        }
        keys.push(key.clone());
    }

    if keys.is_empty() {
        return Err(invalid_data(
            "embedded SSH requires at least one authorized controller key",
        ));
    }
    Ok(keys)
}

pub(super) fn prepare(config: &AgentConfig) -> io::Result<PreparedEmbeddedSshConfig> {
    if config.user.trim().is_empty() {
        return Err(invalid_data("SSH user must not be empty"));
    }
    Ok(PreparedEmbeddedSshConfig {
        expected_user: Arc::<str>::from(config.user.trim()),
        host_key: load_host_key(&config.host_key)?,
        authorized_keys: Arc::new(load_authorized_keys(&config.authorized_keys)?),
    })
}
fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        return Err(invalid_data("SSH key input must be a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SSH secret file permissions are not private",
            ));
        }
    }
    #[cfg(windows)]
    {
        validate_private_acl(path)?;
    }
    std::fs::read(path)
}

pub(crate) fn validate_private_path(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_data("private path must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private path is group/world accessible",
            ));
        }
    }
    #[cfg(windows)]
    validate_private_acl(path)?;
    Ok(())
}

#[cfg(windows)]
fn validate_private_acl(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    crate::private_fs::windows::validate_acl(
        path,
        &metadata,
        crate::private_fs::windows::AllowedPrincipals::OwnerSystemAdministrators,
        true,
    )
}

pub(super) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
