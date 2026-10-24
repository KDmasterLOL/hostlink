use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::inventory::remove(args.name).await
}
