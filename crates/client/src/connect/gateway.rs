//! Exact SSH pin, user, and approved gateway route validation.

use std::net::SocketAddr;

use russh::keys::PublicKey;

use super::{SshClientError, identity::load_identity};
use crate::GatewayHop;

pub(super) fn parse_pin(pin: &str) -> Result<PublicKey, SshClientError> {
    if pin.contains('\n') || pin.contains('\r') {
        return Err(SshClientError::Invalid(
            "host pin must be one OpenSSH public-key line".into(),
        ));
    }
    PublicKey::from_openssh(pin)
        .map_err(|_| SshClientError::Invalid("invalid OpenSSH host pin".into()))
}

pub(super) fn validate_user(user: &str) -> Result<(), SshClientError> {
    if user.is_empty()
        || user.len() > 64
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(SshClientError::Invalid("SSH user name is invalid".into()));
    }
    Ok(())
}

fn validate_gateway(gateway: &GatewayHop) -> Result<(), SshClientError> {
    validate_user(&gateway.user)?;
    if gateway.reverse_port == 0 {
        return Err(SshClientError::Invalid(
            "gateway reverse port must be nonzero".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_gateway_routes(
    primary: &GatewayHop,
) -> Result<Vec<(SocketAddr, String, russh::keys::PrivateKey, PublicKey)>, SshClientError> {
    if primary.alternates.len() > 15 {
        return Err(SshClientError::Invalid(
            "at most 16 approved gateway routes are allowed".into(),
        ));
    }
    let mut routes = Vec::with_capacity(primary.alternates.len() + 1);
    let mut identities = std::collections::BTreeSet::new();
    let mut pins = std::collections::BTreeSet::new();
    let mut append =
        |address: SocketAddr, user: &str, identity_path: &std::path::Path, pin: &str| {
            validate_user(user)?;
            if !identities.insert((address, user.to_owned())) || !pins.insert(pin.to_owned()) {
                return Err(SshClientError::Invalid(
                    "duplicate approved gateway route or host pin".into(),
                ));
            }
            let key = parse_pin(pin)?;
            let identity = load_identity(identity_path)?;
            if key.algorithm().to_string() != "ssh-ed25519" {
                return Err(SshClientError::Invalid(
                    "gateway pin must be Ed25519".into(),
                ));
            }
            routes.push((address, user.to_owned(), identity, key));
            Ok(())
        };
    validate_gateway(primary)?;
    append(
        primary.address,
        &primary.user,
        &primary.identity,
        &primary.host_public_key,
    )?;
    for alternate in &primary.alternates {
        append(
            alternate.address,
            &alternate.user,
            &alternate.identity,
            &alternate.host_public_key,
        )?;
    }
    Ok(routes)
}

pub(super) fn is_transient_gateway_connect_error(error: &SshClientError) -> bool {
    match error {
        SshClientError::Timeout => true,
        SshClientError::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        SshClientError::Russh(
            russh::Error::ConnectionTimeout | russh::Error::HUP | russh::Error::Disconnect,
        ) => true,
        SshClientError::Russh(russh::Error::IO(error)) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}
