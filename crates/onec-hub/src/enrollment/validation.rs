//! Enrollment identifiers, persistence modes, and Ed25519 key normalization.

use super::super::*;

pub(crate) fn validate_enrollment(input: &EnrollRequest) -> io::Result<()> {
    validate_machine_id(&input.machine_id)?;
    validate_identifier("name", &input.name, 128)?;
    if input.hostname.trim().is_empty() || input.hostname.len() > 255 {
        return Err(invalid("hostname is empty or too long"));
    }
    if let Some(username) = input.username.as_deref()
        && (username.trim().is_empty() || username.len() > 255 || username.contains(['\r', '\n']))
    {
        return Err(invalid(
            "username is empty, too long, or contains a newline",
        ));
    }
    if input.transport != "open_ssh" {
        return Err(invalid("transport must be open_ssh"));
    }
    if let Some(persistence_mode) = input.persistence_mode.as_deref()
        && !matches!(persistence_mode, "user-session" | "windows-service")
    {
        return Err(invalid(
            "persistence_mode must be user-session or windows-service",
        ));
    }
    normalize_public_key(&input.ssh_public_key)?;
    if let Some(key) = input.ssh_host_public_key.as_deref() {
        normalize_public_key(key)?;
    }
    Ok(())
}

pub(crate) fn validate_identifier(kind: &str, value: &str, max: usize) -> io::Result<()> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > max
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(invalid(format!(
            "{kind} must be a canonical identifier containing only ASCII letters, digits, '.', '-' or '_'"
        )));
    }
    Ok(())
}

pub(crate) fn validate_machine_id(value: &str) -> io::Result<()> {
    validate_identifier("machine_id", value, 128)?;
    if value != value.to_ascii_lowercase() {
        return Err(invalid("machine_id must use canonical lowercase form"));
    }
    Ok(())
}

pub(crate) fn normalize_public_key(value: &str) -> io::Result<String> {
    crate::ssh_material::normalize_ed25519_public_key(value)
}
