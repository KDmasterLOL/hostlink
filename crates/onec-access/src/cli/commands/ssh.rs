use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(short = 't', long)]
    pub(crate) tty: bool,
    #[arg(trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::ssh::run(args.name, args.tty, args.command).await
}
