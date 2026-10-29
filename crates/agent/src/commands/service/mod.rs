//! Current-user Agent service management.

mod install;
mod remove;
mod start;
mod status;
mod stop;

use clap::{Args as ClapArgs, Subcommand};
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: ServiceCommand,
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

pub(crate) fn execute(args: Args) -> io::Result<()> {
    match args.command {
        ServiceCommand::Install { root, config } => install::execute(root, config),
        ServiceCommand::Start { root } => start::execute(root),
        ServiceCommand::Stop { root } => stop::execute(root),
        ServiceCommand::Status { root } => status::execute(root),
        ServiceCommand::Remove { root } => remove::execute(root),
    }
}
