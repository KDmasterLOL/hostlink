use clap::Args as ClapArgs;
use hostlink_agent::update::{AgentUpdateOutcome, AgentUpdateRequest, Artifact};
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
    let update = AgentUpdateRequest {
        install_root: args.root,
        artifact: Artifact::new(&args.url, args.sha256, args.target, args.version)?,
    };
    match hostlink_agent::update::apply(&update)? {
        AgentUpdateOutcome::AlreadyCurrent { .. } => {
            println!("Agent package already current");
            Ok(())
        }
        AgentUpdateOutcome::Installed { .. } => {
            println!("Agent package verified and installed");
            Ok(())
        }
    }
}
