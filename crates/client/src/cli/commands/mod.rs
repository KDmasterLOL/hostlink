mod forward;
pub(super) mod hosts;
mod hub;
mod remote;

use crate::cli::{
    args::{Cli, Command},
    commands::hosts::resolve_target_spec,
};
use hostlink::connect::HostConnection;
use std::{error::Error, path::PathBuf};

pub(super) async fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    if let Some(code) = hub::dispatch(&cli.command).await? {
        return Ok(code);
    }
    if let Some(code) = hosts::dispatch(&cli.command).await? {
        return Ok(code);
    }
    if let Command::Migration {
        command:
            crate::cli::args::MigrationCommand::Preflight {
                old_hub,
                old_controller,
                old_agent,
                new_agent,
                new_host,
            },
    } = &cli.command
    {
        let report =
            hostlink::migration::preflight(old_hub, old_controller, old_agent, new_agent, new_host)
                .map_err(std::io::Error::other)?;
        serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
        use std::io::Write;
        std::io::stdout().lock().write_all(b"\n")?;
        return Ok(
            if report
                .hosts
                .iter()
                .any(|host| host.readiness == hostlink::migration::Readiness::Blocked)
            {
                2
            } else {
                0
            },
        );
    }
    if let Some(code) = forward::dispatch(&cli.command).await? {
        return Ok(code);
    }

    if let Command::Probe {
        target, timeout_ms, ..
    } = &cli.command
        && (target.port() == 0 || *timeout_ms == 0)
    {
        return Err("probe target port and timeout must be nonzero".into());
    }
    let (selected_config, selected_host) = selection(&cli.command)?;
    let config_path = match selected_config {
        Some(path) => path,
        None => hub::default_hub_config_path()?,
    };
    let spec = resolve_target_spec(&config_path, selected_host.as_deref()).await?;
    let mut client = HostConnection::connect(&spec).await?;

    // Keep cleanup errors visible alongside any command failure.
    let operation: Result<i32, Box<dyn Error>> = async {
        remote::execute(&mut client, &cli.command)
            .await?
            .ok_or_else(|| "internal remote command dispatch mismatch".into())
    }
    .await;
    let cleanup = client.close().await;
    match (operation, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Err(primary), Err(cleanup)) => {
            Err(format!("operation failed: {primary}; SSH cleanup also failed: {cleanup}").into())
        }
    }
}

fn selection(command: &Command) -> Result<(Option<PathBuf>, Option<String>), Box<dyn Error>> {
    let selected = match command {
        Command::Check { config, host }
        | Command::Exec { config, host, .. }
        | Command::Upload { config, host, .. }
        | Command::Download { config, host, .. }
        | Command::Forward { config, host, .. }
        | Command::Rdp { config, host, .. }
        | Command::Probe { config, host, .. } => (config.clone(), host.clone()),
        _ => return Err("internal command selection mismatch".into()),
    };
    Ok(selected)
}
