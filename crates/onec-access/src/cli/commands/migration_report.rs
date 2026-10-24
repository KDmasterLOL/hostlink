use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::inventory::migration_report(args.json).await
}
