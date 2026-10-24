use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) listen_host: String,
    #[arg(long)]
    pub(crate) listen_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) target_host: String,
    #[arg(long)]
    pub(crate) target_port: u16,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::transport::forward(
        args.name,
        args.listen_host,
        args.listen_port,
        args.target_host,
        args.target_port,
    )
    .await
}
