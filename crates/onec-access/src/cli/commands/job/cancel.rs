use clap::Args as ClapArgs;
use hostlink_protocol::AgentResponseKind;
#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) job_id: String,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args { name, job_id, json } = args;
    let response = super::super::super::jobs::client(&name)
        .await?
        .job_cancel(job_id)
        .await?;
    let AgentResponseKind::JobCancelRequested { job } = response else {
        return Err(crate::invalid_config(
            "remote agent returned a non-job-cancel response".to_owned(),
        ));
    };
    if json {
        super::super::super::jobs::print_job(&job, true);
    } else if job.state.is_terminal() {
        println!(
            "{} already {}",
            job.job_id,
            super::super::super::jobs::state_name(job.state)
        );
    } else {
        println!("Cancellation requested: {}", job.job_id);
    }
    Ok(())
}
