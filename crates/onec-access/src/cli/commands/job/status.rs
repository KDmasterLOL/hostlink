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
        .job_status(job_id)
        .await?;
    let AgentResponseKind::JobStatus { job } = response else {
        return Err(crate::invalid_config(
            "remote agent returned a non-job-status response".to_owned(),
        ));
    };
    super::super::super::jobs::print_job(&job, json);
    Ok(())
}
