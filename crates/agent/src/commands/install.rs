use clap::Args as ClapArgs;
use hostlink_agent::installation::{InstallOptions, install};
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    hub_url: String,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    user: String,
    /// Zero-based index in the Hub-approved gateway list.
    #[arg(long)]
    pub(crate) gateway_index: Option<usize>,
    /// Additional private Hub CA (PEM); normal certificate verification remains enabled.
    #[arg(long)]
    hub_ca_cert: Option<PathBuf>,
    /// Exact existing machine identity from the authenticated Controller invitation.
    #[arg(long)]
    machine_id: Option<hostlink_hub::MachineId>,
    /// Replace lost SSH keys only with an explicit operator rotation invite and typed local confirmation.
    #[arg(long, requires = "machine_id")]
    replace_identity: bool,
}

pub(crate) async fn execute(args: Args) -> io::Result<()> {
    let result = install(
        &InstallOptions {
            machine_id: args.machine_id,
            replace_identity: args.replace_identity,
            hub_url: args.hub_url,
            token_file: args.token_file,
            name: args.name,
            user: args.user,
            gateway_index: args.gateway_index,
        },
        args.hub_ca_cert.as_deref(),
    )
    .await?;
    println!("Agent installed: {}", result.machine_id);
    println!("Configuration: {}", result.config_path.display());
    Ok(())
}
