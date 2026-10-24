use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
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
    let expected_job_id = job.job_id.clone();
    let response = client.job_cancel(expected_job_id.clone()).await?;
    let onec_agent_protocol::AgentResponseKind::JobCancelRequested { job } = response else {
        return Err(crate::invalid_config(
            "agent returned an unexpected durable run-local cancellation response".to_owned(),
        ));
    };
    controller::ensure_run_local_job(&job, &run_id)?;
    if job.job_id != expected_job_id {
        return Err(crate::invalid_config(
            "agent cancellation belongs to a different durable run-local job".to_owned(),
        ));
    }
    controller::print_job(&job, json);
    Ok(())
}
