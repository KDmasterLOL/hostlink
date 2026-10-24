use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    let Args {
        target,
        run_id,
        json,
    } = args;
    let (machine_id, _, client) = controller::resolve(&target).await?;
    let job = controller::status_by_run(
        &client,
        &controller::controller_data_root()?,
        &machine_id,
        &run_id,
    )
    .await?;
    controller::print_job(&job, json);
    Ok(())
}
