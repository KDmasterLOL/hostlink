use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(long, default_value_t = 13389)]
    pub(crate) listen_port: u16,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::transport::rdp(args.name, args.listen_port).await
}
