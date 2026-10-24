use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) root: String,
    pub(crate) path: String,
    #[arg(long)]
    pub(crate) recursive: bool,
    #[arg(long)]
    pub(crate) missing_ok: bool,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::transport::remove_scoped(
        args.name,
        args.root,
        args.path,
        args.recursive,
        args.missing_ok,
        args.json,
    )
    .await
}
