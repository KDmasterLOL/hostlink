//! Clap command-line schema for hub validation and serving.

use super::*;

#[derive(Debug, Parser)]
#[command(
    name = "onec-hub",
    version,
    about = "Enrollment and discovery hub for onec-agent fleets"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Validate configuration and state without starting a listener.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the loopback HTTP API. Put HTTPS/reverse-proxy termination in front of it.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn server_cli_exposes_only_check_and_serve() {
        Cli::try_parse_from(["onec-hub", "check", "--config", "hub.json"])
            .expect("check command must parse");
        Cli::try_parse_from(["onec-hub", "serve", "--config", "hub.json"])
            .expect("serve command must parse");

        let error = Cli::try_parse_from(["onec-hub", "access", "list"])
            .expect_err("controller access must not remain in the hub server CLI");
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    }
}
