use clap::Args as ClapArgs;
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    root: PathBuf,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    hostlink_agent::update::finalize_fresh_install(&args.root)
}
