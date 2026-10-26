//! Minimal HostLink Agent user-session executable.

use clap::{Parser, Subcommand};
use hostlink_agent::{
    AgentConfig,
    enrollment::EnrollmentOptions,
    ssh,
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
        /// Load and verify lifecycle configuration from the private root marker.
        #[arg(long, hide = true)]
        managed_service: bool,
        /// Internal owner-bound startup; one-use admission arrives through inherited stdin.
        #[arg(long, hide = true)]
        maintenance_start: bool,
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
    /// Enroll a fresh user-owned Agent root with a one-use Hub invitation.
    Enroll {
        #[arg(long)]
        hub_url: String,
        /// Additional private Hub CA in PEM format; certificate verification remains enabled.
        #[arg(long)]
        hub_ca_cert: Option<PathBuf>,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        gateway_index: Option<usize>,
        /// Retain the pending marker until bootstrap-finalize verifies package publication.
        #[arg(long, hide = true)]
        retain_pending: bool,
    },
    /// Verify a fresh-install ZIP with this exact target-specific executable sidecar.
    BootstrapVerify {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Finish a verified fresh install and remove its enrollment reconciliation marker.
    BootstrapFinalize {
        #[arg(long)]
        root: PathBuf,
    },
    /// Manage the new Agent in the current user's service manager.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Register a private user service; the first start is explicit.
    Install {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Start only the service owned by this exact install root.
    Start {
        #[arg(long)]
        root: PathBuf,
    },
    /// Stop only the service owned by this exact install root.
    Stop {
        #[arg(long)]
        root: PathBuf,
    },
    /// Report service state, owned process identity and SSH loopback banner.
    Status {
        #[arg(long)]
        root: PathBuf,
    },
    /// Uninstall the owned executable and service integration; retain enrollment data and jobs.
    Remove {
        #[arg(long)]
        root: PathBuf,
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
        Command::Run {
            config,
            managed_service,
            maintenance_start,
        } => {
            #[cfg(windows)]
            let managed_control = if managed_service || maintenance_start {
                Some(hostlink_agent::service::validate_managed_run(
                    &config,
                    maintenance_start,
                )?)
            } else {
                None
            };
            #[cfg(not(windows))]
            if managed_service || maintenance_start {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "managed lifecycle mode is available only on Windows",
                ));
            }
            let config = load_config(&config)?;
            let shutdown = tokio_util::sync::CancellationToken::new();
            let signal_shutdown = shutdown.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    signal_shutdown.cancel();
                }
            });
            // ssh::serve owns the outbound tunnel when the config contains
            // gateway routes. Starting tunnel::run here as well would race
            // the same Agent identity for its uniquely assigned remote port.
            #[cfg(windows)]
            if let Some((pipe, token)) = managed_control {
                let control_config = config.clone();
                let control_shutdown = shutdown.clone();
                let control_finished = tokio_util::sync::CancellationToken::new();
                let server_shutdown = shutdown.clone();
                let mut server = Box::pin(ssh::serve(&config, server_shutdown.cancelled_owned()));
                let control = Box::pin(hostlink_agent::service::control_loop(
                    &control_config,
                    pipe,
                    token,
                    control_shutdown,
                    control_finished.clone(),
                ));
                tokio::select! {
                    result = &mut server => {
                        control_finished.cancel();
                        result?;
                    },
                    result = control => {
                        shutdown.cancel();
                        control_finished.cancel();
                        if let Err(error) = result {
                            let _ = server.await;
                            return Err(error);
                        }
                        server.await?;
                    }
                }
            } else {
                ssh::serve(&config, shutdown.cancelled_owned()).await?;
            }
            #[cfg(not(windows))]
            ssh::serve(&config, shutdown.cancelled_owned()).await?;
            Ok(())
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
        Command::Enroll {
            hub_url,
            hub_ca_cert,
            token_file,
            root,
            name,
            user,
            gateway_index,
            retain_pending,
        } => {
            let result = hostlink_agent::enrollment::prepare_enrollment_with_ca(
                &EnrollmentOptions {
                    hub_url,
                    token_file,
                    install_root: root,
                    name,
                    user,
                    gateway_index,
                    retain_pending,
                },
                hub_ca_cert.as_deref(),
            )
            .await?;
            println!("Agent enrolled: {}", result.machine_id);
            println!("Configuration: {}", result.config_path.display());
            println!(
                "Run with: hostlink-agent run --config {}",
                result.config_path.display()
            );
            Ok(())
        }
        Command::BootstrapVerify {
            archive,
            sha256,
            target,
            version,
            output,
        } => hostlink_agent::update::verify_fresh_package(
            &archive, &sha256, &target, &version, &output,
        ),
        Command::BootstrapFinalize { root } => {
            hostlink_agent::update::finalize_fresh_install(&root)
        }
        Command::Service { command } => match command {
            ServiceCommand::Install { root, config } => {
                hostlink_agent::service::install(&root, &config)
            }
            ServiceCommand::Start { root } => hostlink_agent::service::start(&root),
            ServiceCommand::Stop { root } => hostlink_agent::service::stop(&root),
            ServiceCommand::Remove { root } => hostlink_agent::service::remove(&root),
            ServiceCommand::Status { root } => {
                let status = hostlink_agent::service::status(&root)?;
                println!("{}", status.detail);
                println!(
                    "installed={} active={} owner_uid={} owner_sid={} pid={} executable_sha256={} ssh_banner={} local_enrollment_metadata={} hub_reachability=not_checked",
                    status.installed,
                    status.active,
                    status
                        .owner_uid
                        .map_or_else(|| "-".into(), |uid| uid.to_string()),
                    status.owner_sid.as_deref().unwrap_or("-"),
                    status.pid.map_or_else(|| "-".into(), |p| p.to_string()),
                    status.executable_sha256.as_deref().unwrap_or("-"),
                    status.ssh_banner,
                    status.local_enrollment
                );
                if !status.installed || !status.active || !status.ssh_banner {
                    return Err(io::Error::other("Agent service is not healthy"));
                }
                Ok(())
            }
        },
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
