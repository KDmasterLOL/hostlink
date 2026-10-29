//! Reusable CLI-side input handling, independent of any particular command.

use hostlink_agent::AgentConfig;
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

pub(crate) fn load_config(path: &Path) -> io::Result<AgentConfig> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Agent config must be a bounded regular file without symlinks",
        ));
    }
    let mut file = File::open(path)?.take(MAX_CONFIG_BYTES + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Agent config exceeds size limit",
        ));
    }
    let mut config: AgentConfig = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.resolve_relative_paths(base);
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_rejects_public_ssh_listener_and_symlink_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("agent.json");
        fs::write(&config, br#"{"listen":"0.0.0.0:27322","user":"hostlink","host_key":"key","authorized_keys":"authorized_keys","jobs_root":"jobs","gateway":null}"#).unwrap();
        assert!(load_config(&config).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("config-symlink.json");
            std::os::unix::fs::symlink(&config, &link).unwrap();
            assert!(load_config(&link).is_err());
        }
    }
}
