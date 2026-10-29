use crate::shared::load_config;
use clap::Args as ClapArgs;
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    config: PathBuf,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    let _config = load_config(&args.config)?;
    println!("Agent configuration: valid");
    Ok(())
}
