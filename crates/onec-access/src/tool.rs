//! OpenSSH executable resolution owned by the access product.

use crate::AppResult;
use std::{
    env,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Resolved operator-facing OpenSSH executable.
pub struct ResolvedTool {
    /// Concrete executable path.
    pub path: PathBuf,
}

/// Resolves the OpenSSH client from `ONEC_ACCESS_SSH` or the current PATH.
///
/// # Errors
///
/// Returns [`crate::AppError`] when an explicit override is not a file or no executable can be found.
pub fn resolve_ssh_tool() -> AppResult<ResolvedTool> {
    if let Some(path) = env::var_os("ONEC_ACCESS_SSH").map(PathBuf::from) {
        return resolve_explicit(path);
    }
    if let Some(path) = path_lookup(if cfg!(windows) { "ssh.exe" } else { "ssh" }) {
        return Ok(ResolvedTool { path });
    }
    Err(crate::not_found_error(
        "OpenSSH client; set ONEC_ACCESS_SSH to an executable path".to_owned(),
    ))
}

fn resolve_explicit(path: PathBuf) -> AppResult<ResolvedTool> {
    if !path.is_file() {
        return Err(crate::not_found_error(format!(
            "configured OpenSSH executable {}",
            path.display()
        )));
    }
    Ok(ResolvedTool { path })
}

fn path_lookup(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| executable_candidate(candidate))
}

fn executable_candidate(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .ok()
            .is_some_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        true
    }
}
