mod forward;
pub(super) mod hosts;
mod hub;
mod remote;

use crate::cli::args::{Cli, Command, MigrationCommand};
use std::{
    error::Error,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub(super) async fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    match cli.command {
        Command::Migration {
            command:
                MigrationCommand::Preflight {
                    old_hub,
                    old_controller,
                    old_agent,
                    new_agent,
                    new_host,
                },
        } => {
            let report = hostlink::migration::preflight(
                &old_hub,
                &old_controller,
                &old_agent,
                &new_agent,
                &new_host,
            )
            .map_err(std::io::Error::other)?;
            serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
            std::io::stdout().lock().write_all(b"\n")?;
            Ok(
                if report
                    .hosts
                    .iter()
                    .any(|host| host.readiness == hostlink::migration::Readiness::Blocked)
                {
                    2
                } else {
                    0
                },
            )
        }
        Command::Hub { command } => hub::hub_command(&command).await,
        Command::List { check, json } => hosts::list_command(check, json).await,
        Command::Info { host } => hosts::info(&host).await,
        Command::Verify { host } => hosts::verify(&host).await,
        Command::Invite(args) => hub::invite(args).await,
        Command::DisplayName { host, display_name } => {
            hub::display_name(&host, &display_name).await
        }
        Command::Remove { host, yes } => hub::remove(&host, yes).await,
        Command::Check { host_target } => remote::check(&host_target).await,
        Command::Forward {
            host_target,
            listen,
            target,
        } => forward::forward_cli(&host_target, listen, target).await,
        Command::Rdp {
            host_target,
            listen_port,
        } => {
            let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3389);
            forward::forward_cli(&host_target, listen, target).await
        }
        Command::Probe {
            host_target,
            target,
            timeout_ms,
        } => remote::probe(&host_target, target, timeout_ms).await,
        Command::Exec {
            host_target,
            detach,
            timeout_seconds,
            board_port,
            os,
            command,
            stdin_file,
        } => {
            if detach {
                let port = board_port.ok_or("--board-port is required with --detach")?;
                let target_os = if let Some(name) = &host_target.host {
                    let path = match &host_target.config {
                        Some(p) => p.clone(),
                        None => hub::default_hub_config_path()?,
                    };
                    let (hub, _) = hostlink::hub::HubClient::from_file(&path)?;
                    let host = hub.resolve_host(name).await?;
                    match host.os.as_str() {
                        "linux" | "windows" => host.os,
                        other => {
                            return Err(format!(
                                "unsupported or unknown target OS from Hub: {other}"
                            )
                            .into());
                        }
                    }
                } else {
                    os.clone().ok_or(
                        "--os linux|windows is required for detached exec with direct --config",
                    )?
                };
                if stdin_file.is_some() {
                    return Err("--stdin-file cannot be used with --detach".into());
                }
                remote::exec_detached(&host_target, port, &command, &target_os, timeout_seconds)
                    .await
            } else {
                if board_port.is_some() || os.is_some() || timeout_seconds.is_some() {
                    return Err(
                        "--board-port, --os, and --timeout-seconds are valid only with --detach"
                            .into(),
                    );
                }
                remote::exec(&host_target, &command, stdin_file.as_deref()).await
            }
        }
        Command::Job {
            command:
                crate::cli::args::JobCommand::Status {
                    host_target,
                    board_port,
                    job_id,
                },
        } => remote::job_status(&host_target, board_port, &job_id).await,
        Command::Upload {
            host_target,
            local,
            remote,
        } => remote::upload(&host_target, &local, &remote).await,
        Command::Download {
            host_target,
            remote,
            local,
        } => remote::download(&host_target, &remote, &local).await,
    }
}
