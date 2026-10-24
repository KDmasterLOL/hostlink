use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) url: String,
    #[arg(long)]
    pub(crate) gateway: String,
    #[arg(long)]
    pub(crate) gateway_user: String,
    #[arg(long, default_value_t = 22)]
    pub(crate) gateway_port: u16,
    #[arg(long)]
    pub(crate) identity: Option<PathBuf>,
    #[arg(long)]
    pub(crate) known_hosts: Option<PathBuf>,
    #[arg(long)]
    pub(crate) release_base_url: Option<String>,
    #[arg(long, conflicts_with = "token_file")]
    pub(crate) token_env: Option<String>,
    #[arg(long, conflicts_with = "token_env")]
    pub(crate) token_file: Option<PathBuf>,
}

pub(super) fn run(args: Args) -> onec_access::AppResult<()> {
    super::super::config::configure(super::super::config::HubConfigureArgs {
        url: args.url,
        gateway: args.gateway,
        gateway_user: args.gateway_user,
        gateway_port: args.gateway_port,
        identity: args.identity,
        known_hosts: args.known_hosts,
        release_base_url: args.release_base_url,
        token_env: args.token_env,
        token_file: args.token_file,
    })
}
