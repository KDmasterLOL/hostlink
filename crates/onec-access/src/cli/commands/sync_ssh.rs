use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) no_install_include: bool,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::ssh::sync(args.no_install_include, args.json).await
}
