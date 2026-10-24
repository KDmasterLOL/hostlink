use clap::Args as ClapArgs;
use onec_agent_protocol::AgentResponseKind;
use std::path::PathBuf;
#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) job_id: String,
    pub(crate) local_dir: PathBuf,
    #[arg(long)]
    pub(crate) overwrite: bool,
    #[arg(long)]
    pub(crate) cleanup: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    let Args {
        name,
        job_id,
        local_dir,
        overwrite,
        cleanup,
    } = args;
    let client = super::super::super::jobs::client(&name).await?;
    let response = client.job_status(job_id.clone()).await?;
    let AgentResponseKind::JobStatus { job } = response else {
        return Err(crate::invalid_config(
            "remote agent returned a non-job-status response".to_owned(),
        ));
    };
    if !job.state.is_terminal() {
        return Err(crate::invalid_config(format!(
            "job {} is {}; results are available only after terminal completion",
            job.job_id,
            super::super::super::jobs::state_name(job.state)
        )));
    }
    let result_set = job.result_set.ok_or_else(|| {
        crate::invalid_config(format!(
            "terminal job {} has no published result metadata",
            job.job_id
        ))
    })?;
    if result_set.owner().job_id() != Some(job.job_id.as_str()) {
        return Err(crate::invalid_config(
            "job status returned result metadata for a different owner".to_owned(),
        ));
    }
    super::super::super::jobs::download_result_set(
        &client,
        &result_set,
        &local_dir,
        overwrite,
        cleanup,
    )
    .await?;
    Ok(())
}
