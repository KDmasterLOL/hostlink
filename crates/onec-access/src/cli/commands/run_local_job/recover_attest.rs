use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    /// Exact challenge used by the original one-shot attestation request.
    #[arg(long)]
    pub(crate) challenge: String,
    /// Independently pinned Ed25519 public key as 64 lowercase/uppercase hex digits.
    #[arg(long)]
    pub(crate) trusted_public_key: PathBuf,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    let Args {
        target,
        run_id,
        challenge,
        trusted_public_key,
    } = args;
    crate::cli::native_attestation::collect(&target, &run_id, &challenge, &trusted_public_key, true)
        .await
}
