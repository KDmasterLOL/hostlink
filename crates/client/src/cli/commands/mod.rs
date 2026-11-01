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
            command,
            stdin_file,
        } => remote::exec(&host_target, &command, stdin_file.as_deref()).await,
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
