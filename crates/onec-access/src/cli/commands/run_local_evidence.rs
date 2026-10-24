use clap::{Args as ClapArgs, Subcommand};

mod verify;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Verify(verify::Args),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(super) fn run(args: Args) -> onec_access::AppResult<()> {
    match args.command {
        Command::Verify(args) => verify::run(args),
    }
}
