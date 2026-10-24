use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    /// Independently pinned stable Hub machine identity; this command performs no Hub access.
    #[arg(long)]
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    /// Exact challenge supplied when the observation was collected.
    #[arg(long)]
    pub(crate) challenge: String,
    /// Independently pinned Ed25519 public key; never loaded from the receipt.
    #[arg(long)]
    pub(crate) trusted_public_key: PathBuf,
    #[arg(long)]
    pub(crate) stdout_log: PathBuf,
    #[arg(long)]
    pub(crate) stderr_log: PathBuf,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        machine_id,
        run_id,
        challenge,
        trusted_public_key,
        stdout_log,
        stderr_log,
    } = args;
    crate::cli::native_invocation_observation::verify_local_logs(
        &machine_id,
        &run_id,
        &challenge,
        &trusted_public_key,
        &stdout_log,
        &stderr_log,
    )
}
