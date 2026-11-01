//! Agent command-line arguments and dispatch.

use crate::commands;
use clap::{Parser, Subcommand};
use std::io;

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
    Check(commands::check::Args),
    /// Serve SSH/SFTP and optional outbound reverse SSH until terminated.
    Run(commands::run::Args),
    /// Update a stopped Agent from GitHub Releases using its private credential file.
    Update(commands::update::Args),
    /// Enroll a fresh user-owned Agent root with a one-use Hub invitation.
    Enroll(commands::enroll::Args),
    /// Install this bootstrap-verified binary and enroll at the stable per-user location.
    Install(commands::install::Args),
    /// Machine-readable build identity used by the offline updater.
    #[command(hide = true)]
    BinaryInfo,
    /// Manage the new Agent in the current user's service manager.
    Service(commands::service::Args),
}

pub(crate) async fn run() -> io::Result<()> {
    match Cli::parse().command {
        Command::Check(args) => commands::check::execute(args),
        Command::Run(args) => commands::run::execute(args).await,
        Command::Update(args) => commands::update::execute(args),
        Command::Enroll(args) => commands::enroll::execute(args).await,
        Command::Install(args) => commands::install::execute(args).await,
        Command::BinaryInfo => {
            println!(
                "{}",
                serde_json::to_string(&hostlink_agent::installation::current_binary_identity())?
            );
            Ok(())
        }
        Command::Service(args) => commands::service::execute(args),
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
