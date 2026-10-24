use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::inventory::verify(args.name, args.json).await
}
