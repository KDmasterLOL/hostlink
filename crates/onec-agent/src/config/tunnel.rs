//! Managed reverse-SSH tunnel validation.
//!
//! The outbound SSH session is library-owned by russh. The ssh.program field remains
//! deserialize-only legacy residue so installed agent.json files survive the migration without
//! retaining an external SSH process boundary.

use super::*;

impl SshTunnelConfig {
    pub(crate) fn validate(&self, local_target_port: u16) -> io::Result<()> {
        self.validate_static(local_target_port)
    }

    pub(crate) fn validate_static(&self, local_target_port: u16) -> io::Result<()> {
        if self.gateways.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one gateway endpoint is required",
            ));
        }
        if self.remote_port == 0 || local_target_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH and control ports must be non-zero",
            ));
        }
        self.identity_path()?;
        self.known_hosts_path()?;

        let mut endpoints = std::collections::BTreeSet::new();
        for gateway in &self.gateways {
            if gateway.host.trim().is_empty() || gateway.user.trim().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gateway host and user are required",
                ));
            }
            if gateway.port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gateway ports must be non-zero",
                ));
            }
            if !endpoints.insert((gateway.host.trim().to_ascii_lowercase(), gateway.port)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "gateway host/port entries must be unique",
                ));
            }
            if let Some(proxy) = &gateway.tls_proxy {
                validate_tls_proxy(proxy)?;
            }
        }
        Ok(())
    }

    pub(crate) fn identity_path(&self) -> io::Result<&Path> {
        self.identity
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed reverse SSH requires an explicit identity",
                )
            })
    }

    pub(crate) fn known_hosts_path(&self) -> io::Result<&Path> {
        self.known_hosts
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed reverse SSH requires an explicit pinned known_hosts file",
                )
            })
    }
}

fn validate_tls_proxy(proxy: &SshTlsProxyConfig) -> io::Result<()> {
    if proxy.program.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_proxy.program must not be empty",
        ));
    }
    if proxy.server_name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_proxy.server_name must not be empty",
        ));
    }
    if proxy
        .server_name
        .contains(|c: char| c.is_whitespace() || c == '\'' || c == '"')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_proxy.server_name contains unsafe characters",
        ));
    }
    if let Some(alpn) = &proxy.alpn
        && (alpn.trim().is_empty()
            || alpn.contains(|c: char| c.is_whitespace() || c == '\'' || c == '"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls_proxy.alpn contains unsafe characters",
        ));
    }
    Ok(())
}
