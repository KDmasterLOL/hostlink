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
    /// Exact portable name from the signed result set.
    #[arg(long)]
    pub(crate) artifact_name: String,
    /// Local artifact copy to verify.
    #[arg(long)]
    pub(crate) artifact_file: PathBuf,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        machine_id,
        run_id,
        challenge,
        trusted_public_key,
        artifact_name,
        artifact_file,
    } = args;
    crate::cli::native_invocation_observation::verify_local_result(
        &machine_id,
        &run_id,
        &challenge,
        &trusted_public_key,
        &artifact_name,
        &artifact_file,
    )
}
