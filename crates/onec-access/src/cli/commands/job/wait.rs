use clap::Args as ClapArgs;
use hostlink_protocol::AgentJobState;
use std::{path::PathBuf, time::Duration};
#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) job_id: String,
    #[arg(long, default_value_t = 500)]
    pub(crate) interval_ms: u64,
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        name,
        job_id,
        interval_ms,
        timeout_seconds,
        json,
    } = args;
    let client = super::super::super::jobs::client(&name).await?;
    let interval = Duration::from_millis(interval_ms.max(100));
    let job = super::super::super::jobs::wait_for_job_status(
        &job_id,
        interval,
        timeout_seconds,
        |job_id| client.job_status(job_id),
    )
    .await?;
    super::super::super::jobs::print_job(&job, json);
    match job.state {
        AgentJobState::Succeeded => Ok(()),
        AgentJobState::Failed => Err(crate::process_failed_error(
            PathBuf::from(format!("remote:{name}:job:{}", job.job_id)),
            "managed job".to_owned(),
            job.exit_code,
            job.message
                .unwrap_or_else(|| "managed job failed".to_owned()),
        )),
        AgentJobState::Canceled | AgentJobState::Interrupted => {
            Err(crate::invalid_config(format!(
                "managed job {} ended as {}",
                job.job_id,
                super::super::super::jobs::state_name(job.state)
            )))
        }
        AgentJobState::Queued | AgentJobState::Running => unreachable!(),
    }
}
