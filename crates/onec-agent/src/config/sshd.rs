//! User-mode sshd validation policy.
//!
//! The managed sshd must bind exactly one loopback port, disable passwords, and require public keys.

use super::*;

const SSHD_CONFIG_MAX_BYTES: usize = 256 * 1024;

impl SshServerConfig {
    pub(super) fn validate(&self) -> io::Result<()> {
        if self.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ssh_server.port must be non-zero",
            ));
        }
        if !self.program.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("ssh_server program not found: {}", self.program.display()),
            ));
        }
        let bytes =
            onec_core::read_file_bounded(&self.config, SSHD_CONFIG_MAX_BYTES).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "failed to read ssh_server config {}: {error}",
                        self.config.display()
                    ),
                )
            })?;
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ssh_server config {} must be UTF-8: {error}",
                    self.config.display()
                ),
            )
        })?;
        validate_user_sshd_config(text, self.port)
    }
}

pub(crate) fn validate_user_sshd_config(text: &str, expected_port: u16) -> io::Result<()> {
    let mut ports = Vec::new();
    let mut listen_addresses = Vec::new();
    let mut password_auth = None;
    let mut pubkey_auth = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "port" => {
                let port = value.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid Port in sshd_config")
                })?;
                ports.push(port);
            }
            "listenaddress" => listen_addresses.push(value.to_owned()),
            "passwordauthentication" => password_auth = Some(value.to_ascii_lowercase()),
            "pubkeyauthentication" => pubkey_auth = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    if ports.as_slice() != [expected_port] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("user sshd_config must contain exactly `Port {expected_port}`, got {ports:?}"),
        ));
    }
    if listen_addresses.len() != 1 || listen_addresses[0] != "127.0.0.1" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "user sshd_config must contain exactly `ListenAddress 127.0.0.1`, got {listen_addresses:?}"
            ),
        ));
    }
    if password_auth.as_deref() != Some("no") || pubkey_auth.as_deref() != Some("yes") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "user sshd_config must require public-key authentication and disable passwords",
        ));
    }
    Ok(())
}
