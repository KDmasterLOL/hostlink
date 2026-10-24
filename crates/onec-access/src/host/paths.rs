//! Managed and user OpenSSH configuration path resolution.

use super::*;

/// Returns the generated OpenSSH config path owned by onec-access.
///
/// # Errors
///
/// Returns [`crate::AppError`] when the controller config root cannot be determined.
pub fn managed_ssh_config_path() -> AppResult<PathBuf> {
    Ok(config_path()?.with_file_name("ssh_config"))
}

/// Returns the generated pinned target-host known_hosts path owned by onec-access.
///
/// # Errors
///
/// Returns [`crate::AppError`] when the controller config root cannot be determined.
pub fn managed_target_known_hosts_path() -> AppResult<PathBuf> {
    Ok(config_path()?.with_file_name("ssh_known_hosts"))
}

/// Returns the generated pinned gateway known_hosts path owned by onec-access.
pub fn managed_gateway_known_hosts_path() -> AppResult<PathBuf> {
    Ok(config_path()?.with_file_name("ssh_gateway_known_hosts"))
}

/// Resolves the current user's ordinary `~/.ssh/config` path.
///
/// # Errors
///
/// Returns [`crate::AppError`] when the current user's home directory cannot be determined.
pub fn user_ssh_config_path() -> AppResult<PathBuf> {
    let home = directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| {
            crate::invalid_config(
                "cannot determine the current user's home directory for ~/.ssh/config".to_owned(),
            )
        })?;
    Ok(home.join(".ssh").join("config"))
}
