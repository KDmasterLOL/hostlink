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
    /// Apply a digest-pinned Agent-only package; refuses active jobs and unsafe targets.
    Update(commands::update::Args),
    /// Enroll a fresh user-owned Agent root with a one-use Hub invitation.
    Enroll(commands::enroll::Args),
    /// Verify a fresh-install ZIP with this exact target-specific executable sidecar.
    BootstrapVerify(commands::bootstrap_verify::Args),
    /// Finish a verified fresh install and remove its enrollment reconciliation marker.
    BootstrapFinalize(commands::bootstrap_finalize::Args),
    /// Manage the new Agent in the current user's service manager.
    Service(commands::service::Args),
}

pub(crate) async fn run() -> io::Result<()> {
    match Cli::parse().command {
        Command::Check(args) => commands::check::execute(args),
        Command::Run(args) => commands::run::execute(args).await,
        Command::Update(args) => commands::update::execute(args),
        Command::Enroll(args) => commands::enroll::execute(args).await,
        Command::BootstrapVerify(args) => commands::bootstrap_verify::execute(args),
        Command::BootstrapFinalize(args) => commands::bootstrap_finalize::execute(args),
        Command::Service(args) => commands::service::execute(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_cli_commands_retain_their_arguments() {
        let valid = [
            vec!["check", "--config", "agent.json"],
            vec!["run", "--config", "agent.json"],
            vec![
                "run",
                "--config",
                "agent.json",
                "--managed-service",
                "--maintenance-start",
            ],
            vec![
                "update",
                "--root",
                "agent",
                "--archive",
                "agent.zip",
                "--sha256",
                "abc",
                "--target",
                "target",
                "--version",
                "1.0.0",
            ],
            vec![
                "enroll",
                "--hub-url",
                "https://hub.test",
                "--token-file",
                "token",
                "--root",
                "agent",
                "--name",
                "host",
                "--user",
                "agent",
                "--gateway-index",
                "1",
                "--retain-pending",
            ],
            vec![
                "bootstrap-verify",
                "--archive",
                "agent.zip",
                "--sha256",
                "abc",
                "--target",
                "target",
                "--version",
                "1.0.0",
                "--output",
                "output",
            ],
            vec!["bootstrap-finalize", "--root", "agent"],
            vec![
                "service",
                "install",
                "--root",
                "agent",
                "--config",
                "agent.json",
            ],
            vec!["service", "start", "--root", "agent"],
            vec!["service", "stop", "--root", "agent"],
            vec!["service", "status", "--root", "agent"],
            vec!["service", "remove", "--root", "agent"],
        ];
        for args in valid {
            assert!(
                Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args.iter().copied()))
                    .is_ok(),
                "CLI rejected {args:?}"
            );
        }
    }

    #[test]
    fn top_level_and_service_require_subcommands() {
        for args in [vec![], vec!["service"]] {
            assert!(
                Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args.iter().copied()))
                    .is_err()
            );
        }
    }
}
