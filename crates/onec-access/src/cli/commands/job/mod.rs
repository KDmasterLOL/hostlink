use clap::{Args as ClapArgs, Subcommand};

pub(crate) mod cancel;
pub(crate) mod logs;
pub(crate) mod result;
pub(crate) mod start;
pub(crate) mod status;
pub(crate) mod wait;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Start(start::Args),
    Status(status::Args),
    /// Download the fully published results of a terminal job.
    Result(result::Args),
    Logs(logs::Args),
    Cancel(cancel::Args),
    Wait(wait::Args),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    match args.command {
        Command::Start(args) => start::run(args).await,
        Command::Status(args) => status::run(args).await,
        Command::Result(args) => result::run(args).await,
        Command::Logs(args) => logs::run(args).await,
        Command::Cancel(args) => cancel::run(args).await,
        Command::Wait(args) => wait::run(args).await,
    }
}
