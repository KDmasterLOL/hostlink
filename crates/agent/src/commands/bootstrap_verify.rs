use clap::Args as ClapArgs;
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    archive: PathBuf,
    #[arg(long)]
    sha256: String,
    #[arg(long)]
    target: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    output: PathBuf,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    hostlink_agent::bootstrap::verify_fresh_package(
        &args.archive,
        &args.sha256,
        &args.target,
        &args.version,
        &args.output,
    )
}
