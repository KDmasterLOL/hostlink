use clap::Args as ClapArgs;
use hostlink_agent::update::{default_update_root, update};
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Installed Agent root; defaults to the domain's verified installation location.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Exact release version (allows downgrade); defaults to latest stable on GitHub.
    #[arg(long)]
    version: Option<semver::Version>,
}

pub(crate) fn execute(args: Args) -> io::Result<()> {
    let root = match args.root {
        Some(root) => root,
        None => default_update_root()?,
    };
    let updated = update(&root, args.version.as_ref())?;
    if updated {
        println!("Agent package verified and installed");
    } else {
        println!("Agent package already current");
    }
    Ok(())
}
