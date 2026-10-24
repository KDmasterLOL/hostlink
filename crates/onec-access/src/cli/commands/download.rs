use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) remote: String,
    pub(crate) local: PathBuf,
    #[arg(long)]
    pub(crate) overwrite: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::transport::download(args.name, args.remote, args.local, args.overwrite).await
}
