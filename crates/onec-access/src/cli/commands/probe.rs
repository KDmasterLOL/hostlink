use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    #[arg(long, default_value_t = 1500)]
    pub(crate) timeout_ms: u64,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::transport::probe(args.name, args.host, args.port, args.timeout_ms).await
}
