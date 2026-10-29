use clap::Args as ClapArgs;
use hostlink_agent::enrollment::EnrollmentOptions;
use std::{io, path::PathBuf};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    hub_url: String,
    /// Additional private Hub CA in PEM format; certificate verification remains enabled.
    #[arg(long)]
    hub_ca_cert: Option<PathBuf>,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    user: String,
    #[arg(long)]
    gateway_index: Option<usize>,
    /// Retain the pending marker until bootstrap-finalize verifies package publication.
    #[arg(long, hide = true)]
    retain_pending: bool,
}

pub(crate) async fn execute(args: Args) -> io::Result<()> {
    let result = hostlink_agent::enrollment::prepare_enrollment_with_ca(
        &EnrollmentOptions {
            hub_url: args.hub_url,
            token_file: args.token_file,
            install_root: args.root,
            name: args.name,
            user: args.user,
            gateway_index: args.gateway_index,
            retain_pending: args.retain_pending,
        },
        args.hub_ca_cert.as_deref(),
    )
    .await?;
    println!("Agent enrolled: {}", result.machine_id);
    println!("Configuration: {}", result.config_path.display());
    println!(
        "Run with: hostlink-agent run --config {}",
        result.config_path.display()
    );
    Ok(())
}
