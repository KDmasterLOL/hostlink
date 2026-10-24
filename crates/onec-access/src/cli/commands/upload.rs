use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) local: PathBuf,
    pub(crate) remote: String,
    #[arg(long)]
    pub(crate) overwrite: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::transport::upload(args.name, args.local, args.remote, args.overwrite).await
}
