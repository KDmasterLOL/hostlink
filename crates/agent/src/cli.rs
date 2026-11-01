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
    /// Update a stopped Agent from GitHub (latest stable by default) or a pinned URL.
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

    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn all_cli_commands_retain_their_arguments() {
        let valid = [
            vec!["check", "--config", "agent.json"],
            vec!["run", "--config", "agent.json"],
            vec![
                "update",
                "--root",
                "agent",
                "--url",
                "https://artifacts.example/v1.0.0/hostlink-agent-x86_64-unknown-linux-gnu.zip",
                "--sha256",
                SHA256,
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
    fn github_update_accepts_latest_or_exact_version_without_a_root() {
        for args in [vec!["update"], vec!["update", "--version", "1.2.3"]] {
            let parsed = Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args))
                .expect("GitHub release selection must parse without resolving an install root");
            assert!(matches!(parsed.command, Command::Update(_)));
        }
        assert!(Cli::try_parse_from(["hostlink-agent", "update", "--root", "agent"]).is_ok());
    }

    #[test]
    fn manual_update_requires_a_complete_pin_but_root_is_optional() {
        let pin = [
            ("--url", "https://artifacts.example/agent.zip"),
            ("--sha256", SHA256),
            ("--version", "1.2.3"),
            ("--target", "x86_64-unknown-linux-gnu"),
        ];
        for mask in 0..16 {
            let mut args = vec!["hostlink-agent", "update"];
            for (bit, (flag, value)) in pin.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    args.extend([*flag, *value]);
                }
            }
            let expected = matches!(mask, 0 | 4 | 15);
            assert_eq!(Cli::try_parse_from(&args).is_ok(), expected, "{args:?}");
        }
    }

    #[test]
    fn update_rejects_malformed_typed_values() {
        let pin = [
            "hostlink-agent",
            "update",
            "--url",
            "https://artifacts.example/agent.zip",
            "--sha256",
            SHA256,
            "--version",
            "1.2.3",
            "--target",
            "x86_64-unknown-linux-gnu",
        ];
        for (index, invalid) in [
            (3, "not-a-url"),
            (5, "abc"),
            (
                5,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
            ),
            (
                5,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
            ),
            (7, "v1.2.3"),
            (7, "1.2"),
        ] {
            let mut args = pin;
            args[index] = invalid;
            assert!(Cli::try_parse_from(args).is_err(), "CLI accepted {args:?}");
        }
        assert!(Cli::try_parse_from(["hostlink-agent", "update", "--version", "latest"]).is_err());
    }

    #[test]
    fn removed_windows_lifecycle_flags_are_rejected() {
        for flag in ["--managed-service", "--maintenance-start"] {
            assert!(
                Cli::try_parse_from(["hostlink-agent", "run", "--config", "agent.json", flag])
                    .is_err()
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
