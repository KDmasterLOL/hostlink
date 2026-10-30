use crate::AgentConfig;
use russh::keys::{Algorithm, PrivateKey, PublicKey, ssh_key::authorized_keys::AuthorizedKeys};
use std::{
    io::{self, Read},
    path::Path,
    sync::Arc,
};

const HOST_KEY_MAX_BYTES: usize = 64 * 1024;
const AUTHORIZED_KEYS_MAX_BYTES: usize = 1024 * 1024;

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

pub(crate) fn prepare(config: &AgentConfig) -> io::Result<PreparedEmbeddedSshConfig> {
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
    let file = crate::private_fs::open_private(path, false)?;
    let meta = file.metadata()?;
    if meta.len() > limit as u64 {
        return Err(invalid_data("SSH key input must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid_data("SSH key input exceeds size limit"));
    }
    Ok(bytes)
}

pub(super) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
