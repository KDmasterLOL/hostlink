use clap::Args as ClapArgs;
use hostlink_agent::update::update;
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    url: String,
    #[arg(long)]
    sha256: String,
    #[arg(long)]
    target: String,
    #[arg(long)]
    version: String,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    if update(
        &args.root,
        &args.url,
        &args.sha256,
        &args.target,
        &args.version,
    )? {
        println!("Agent package verified and installed");
    } else {
        println!("Agent package already current");
    }
    Ok(())
}
