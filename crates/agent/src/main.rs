//! Minimal HostLink Agent user-session executable.

use clap::{Parser, Subcommand};
use hostlink_agent::{
    AgentConfig, ssh,
    update::{AgentUpdateOutcome, AgentUpdateRequest},
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Parser)]
#[command(
    name = "hostlink-agent",
    version,
    about = "Unprivileged embedded-SSH Agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and validate a user-owned Agent configuration (does not connect).
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Serve SSH/SFTP and optional outbound reverse SSH until terminated.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply a digest-pinned Agent-only package; refuses active jobs and unsafe targets.
    Update {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        version: String,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("hostlink-agent: {error}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> io::Result<()> {
    match cli.command {
        Command::Check { config } => {
            let _config = load_config(&config)?;
            println!("Agent configuration: valid");
            Ok(())
        }
        Command::Run { config } => {
            let config = load_config(&config)?;
            ssh::serve(&config, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        }
        Command::Update {
            root,
            archive,
            sha256,
            target,
            version,
        } => {
            let update = AgentUpdateRequest {
                install_root: root,
                archive_file: archive,
                archive_sha256: sha256,
                target,
                version,
            };
            match hostlink_agent::update::apply(&update)? {
                AgentUpdateOutcome::AlreadyCurrent { .. } => {
                    println!("Agent package already current");
                    Ok(())
                }
                AgentUpdateOutcome::Installed { .. } => {
                    println!("Agent package verified and installed");
                    Ok(())
                }
                AgentUpdateOutcome::DeferredActiveJobs { job_ids } => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("Agent update deferred: {} jobs not terminal", job_ids.len()),
                )),
            }
        }
    }
}

fn load_config(path: &Path) -> io::Result<AgentConfig> {
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
    if config.host_key.is_relative() {
        config.host_key = base.join(config.host_key);
    }
    if config.authorized_keys.is_relative() {
        config.authorized_keys = base.join(config.authorized_keys);
    }
    if config.jobs_root.is_relative() {
        config.jobs_root = base.join(config.jobs_root);
    }
    if let Some(gateway) = &mut config.gateway {
        if gateway.identity.is_relative() {
            gateway.identity = base.join(&gateway.identity);
        }
        if gateway.host_public_key.is_relative() {
            gateway.host_public_key = base.join(&gateway.host_public_key);
        }
    }
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
