use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::inventory::list(args.json).await
}
