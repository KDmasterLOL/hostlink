use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    /// Fresh verifier challenge (1..=128 UTF-8 bytes), independently pinned by the consumer.
    #[arg(long)]
    pub(crate) challenge: String,
    /// Independently pinned Ed25519 public key as 64 hexadecimal digits.
    #[arg(long)]
    pub(crate) trusted_public_key: PathBuf,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        target,
        run_id,
        challenge,
        trusted_public_key,
    } = args;
    crate::cli::native_invocation_observation::collect(
        &target,
        &run_id,
        &challenge,
        &trusted_public_key,
        false,
    )
    .await
}
