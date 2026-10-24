use crate::cli::mutable_lease;
use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    #[arg(long)]
    pub(crate) abandon_unstarted: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        target,
        run_id,
        abandon_unstarted,
    } = args;
    let (machine_id, _, client) = controller::resolve(&target).await?;
    let data_root = controller::controller_data_root()?;
    if abandon_unstarted {
        client.abandon_run_local(run_id.clone()).await?;
        mutable_lease::release_abandoned_run_local(&data_root, &machine_id, &run_id)?;
        println!("Abandoned unstarted run-local workspace {run_id}");
        return Ok(());
    }
    match controller::status_by_run(&client, &data_root, &machine_id, &run_id).await {
        Ok(job) => {
            if !mutable_lease::durable_run_local_results_complete(&data_root, &machine_id, &run_id)?
            {
                return Err(crate::invalid_config("retrieve results first with `run-local-job results`; reservation and workspace remain owned until that succeeds".to_owned()));
            }
            controller::ensure_run_local_job(&job, &run_id)?;
            if !job.state.is_terminal() {
                return Err(crate::invalid_config(
                    "cannot clean a non-terminal durable run-local job".to_owned(),
                ));
            }
            match client.finalize_run_local_job(job.job_id.clone()).await? {
                hostlink_protocol::AgentResponseKind::PathRemoved { .. } => {}
                _ => {
                    return Err(crate::invalid_config(
                        "agent returned an unexpected run-local finalization response".to_owned(),
                    ));
                }
            }
        }
        Err(error) => {
            client
                .abandon_run_local(run_id.clone())
                .await
                .map_err(|abandon| {
                    abandon.context(format!(
                        "run-local status failed ({error:#}); ownership remains reserved"
                    ))
                })?;
            mutable_lease::release_abandoned_run_local(&data_root, &machine_id, &run_id)?;
            println!("Abandoned unstarted run-local workspace {run_id}");
            return Ok(());
        }
    }
    let job = controller::status_by_run(&client, &data_root, &machine_id, &run_id).await?;
    mutable_lease::release_durable_run_local(&data_root, &machine_id, &run_id, &job.job_id)?;
    mutable_lease::remove_durable_native_invocation_reservation(&data_root, &machine_id, &run_id)?;
    println!("Cleaned durable run-local job {run_id}");
    Ok(())
}
