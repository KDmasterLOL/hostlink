//! OpenSSH scalar, path, alias, host-key, and security-directive encoding policy.

use super::*;
use ssh_key::{Algorithm, PublicKey};

pub(super) fn append_common_security(
    output: &mut String,
    identity: &Path,
    known_hosts: &Path,
    global_known_hosts: &str,
) -> AppResult<()> {
    output.push_str(&format!("    IdentityFile {}\n", ssh_path(identity)?));
    output.push_str(&format!(
        "    UserKnownHostsFile {}\n",
        ssh_path(known_hosts)?
    ));
    output.push_str(&format!("    GlobalKnownHostsFile {global_known_hosts}\n"));
    output.push_str("    StrictHostKeyChecking yes\n");
    output.push_str("    IdentitiesOnly yes\n");
    output.push_str("    IdentityAgent none\n");
    Ok(())
}

pub(super) fn ssh_alias(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(crate::invalid_config(format!(
            "hub host name {value:?} cannot be used as a safe OpenSSH alias"
        )));
    }
    Ok(value.to_owned())
}

pub(super) fn ssh_scalar(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(crate::invalid_config(
            "SSH config value is empty or contains a newline".to_owned(),
        ));
    }
    if value
        .chars()
        .all(|ch| !ch.is_whitespace() && ch != '#' && ch != '"')
    {
        return Ok(value.to_owned());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

pub(super) fn ssh_path(path: &Path) -> AppResult<String> {
    let value = path.to_str().ok_or_else(|| {
        crate::invalid_config("OpenSSH path cannot be represented exactly as UTF-8".to_owned())
    })?;
    let value = value.replace('\\', "/");
    ssh_scalar(&value)
}

pub(super) fn ssh_argv_path(path: &Path) -> AppResult<String> {
    let value = path.to_str().ok_or_else(|| {
        crate::invalid_config("OpenSSH path cannot be represented exactly as UTF-8".to_owned())
    })?;
    Ok(value.replace('\\', "/"))
}

pub(super) fn normalized_ed25519_public_key(value: &str) -> Option<String> {
    if value.contains(['\r', '\n']) {
        return None;
    }
    let mut key = PublicKey::from_openssh(value.trim()).ok()?;
    if key.algorithm() != Algorithm::Ed25519 {
        return None;
    }
    key.set_comment("");
    key.to_openssh().ok()
}

pub(super) fn host_key_alias(agent: &HubAgent) -> String {
    let safe = agent
        .machine_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .collect::<String>();
    format!("onec-ops-machine-{safe}")
}

pub(super) fn null_known_hosts_path() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}
