use crate::cli::mutable_lease;
use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    pub(crate) local_dir: PathBuf,
    #[arg(long)]
    pub(crate) overwrite: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        target,
        run_id,
        local_dir,
        overwrite,
    } = args;
    let (machine_id, _, client) = controller::resolve(&target).await?;
    let data_root = controller::controller_data_root()?;
    let job = controller::status_by_run(&client, &data_root, &machine_id, &run_id).await?;
    controller::ensure_run_local_job(&job, &run_id)?;
    if !job.state.is_terminal() {
        return Err(crate::invalid_config(
            "durable run-local results are available only after terminal completion".to_owned(),
        ));
    }
    let already_downloaded =
        mutable_lease::durable_run_local_results_downloaded(&data_root, &machine_id, &run_id)?;
    if let Some(set) = &job.result_set {
        if set.owner().job_id() != Some(job.job_id.as_str()) {
            return Err(crate::invalid_config(
                "run-local result metadata belongs to a different job".to_owned(),
            ));
        }
        if !already_downloaded {
            crate::cli::jobs::download_result_set(&client, set, &local_dir, overwrite, false)
                .await?;
            mutable_lease::mark_durable_run_local_results_downloaded(
                &data_root,
                &machine_id,
                &run_id,
            )?;
        }
        client.result_cleanup(set.owner().clone()).await?;
    } else if !already_downloaded {
        mutable_lease::mark_durable_run_local_results_downloaded(&data_root, &machine_id, &run_id)?;
    }
    mutable_lease::mark_durable_run_local_results_complete(&data_root, &machine_id, &run_id)?;
    println!("Results retrieved and remote result data cleaned for run {run_id}");
    Ok(())
}
