use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) receipt: PathBuf,
}

pub(super) fn run(args: Args) -> hostlink_access::AppResult<()> {
    let evidence =
        super::super::super::execution_evidence::read_verified(&args.receipt).map_err(|error| {
            hostlink_access::invalid_config(format!("invalid run-local execution receipt: {error}"))
        })?;
    println!(
        "run-local observation integrity checked: exit_code={:?} run_id={} host_id={} target={} effect={}",
        evidence.exit_code,
        evidence.run_id,
        evidence.host_id,
        evidence.target_triple,
        evidence.effect,
    );
    Ok(())
}
