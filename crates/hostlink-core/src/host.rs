use serde::Serialize;
use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};

/// Return the current machine hostname using the platform-native hostname crate.
pub fn system_hostname() -> io::Result<String> {
    normalize_hostname(hostname::get()?)
}

/// Normalize a platform hostname value at the shared runtime boundary.
pub fn normalize_hostname(hostname: OsString) -> io::Result<String> {
    let hostname = hostname.into_string().map_err(|value| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hostname is not UTF-8: {}", value.to_string_lossy()),
        )
    })?;
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hostname is empty",
        ));
    }
    Ok(hostname.to_owned())
}

/// Snapshot of local hostname resolution used to diagnose service startup failures.
#[derive(Debug, Clone, Serialize)]
pub struct HostResolutionDiagnostic {
    /// Local OS hostname.
    pub hostname: String,
    /// Deduplicated addresses resolved for the hostname.
    pub addresses: Vec<IpAddr>,
    /// Resolved non-loopback IPv4 addresses.
    pub non_loopback_ipv4_addresses: Vec<IpAddr>,
    /// Whether any IPv4 address was resolved.
    pub has_ipv4: bool,
    /// Whether at least one non-loopback IPv4 address was resolved.
    pub has_non_loopback_ipv4: bool,
}

/// Resolves the local hostname and reports IPv4/non-loopback reachability characteristics.
///
/// # Errors
///
/// Returns the underlying operating-system error when hostname discovery or address resolution
/// fails.
pub fn host_resolution_diagnostic() -> io::Result<HostResolutionDiagnostic> {
    let hostname = system_hostname()?;
    let mut addresses = (hostname.as_str(), 0)
        .to_socket_addrs()?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    let non_loopback_ipv4_addresses = addresses
        .iter()
        .copied()
        .filter(|address| address.is_ipv4() && !address.is_loopback())
        .collect::<Vec<_>>();
    let has_ipv4 = addresses.iter().any(IpAddr::is_ipv4);
    let has_non_loopback_ipv4 = !non_loopback_ipv4_addresses.is_empty();
    Ok(HostResolutionDiagnostic {
        hostname,
        addresses,
        non_loopback_ipv4_addresses,
        has_ipv4,
        has_non_loopback_ipv4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_normalization_trims_and_rejects_empty_values() {
        assert_eq!(
            normalize_hostname(OsString::from("WORKSTATION-14\r\n")).unwrap(),
            "WORKSTATION-14"
        );
        assert!(normalize_hostname(OsString::from("\r\n")).is_err());
    }
}
