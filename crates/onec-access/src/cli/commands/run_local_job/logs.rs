use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    pub(crate) run_id: String,
    #[arg(long, default_value_t = 65536)]
    pub(crate) tail_bytes: u64,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        target,
        run_id,
        tail_bytes,
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
    let response = client.job_logs(expected_job_id.clone(), tail_bytes).await?;
    let hostlink_protocol::AgentResponseKind::JobLogs {
        job_id,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        stdout_storage_truncated,
        stderr_storage_truncated,
    } = response
    else {
        return Err(crate::invalid_config(
            "agent returned an unexpected durable run-local log response".to_owned(),
        ));
    };
    if job_id != expected_job_id {
        return Err(crate::invalid_config(
            "agent logs belong to a different durable run-local job".to_owned(),
        ));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"job_id":job_id,"run_id":run_id,"stdout":stdout,"stderr":stderr,"stdout_truncated":stdout_truncated,"stderr_truncated":stderr_truncated,"stdout_storage_truncated":stdout_storage_truncated,"stderr_storage_truncated":stderr_storage_truncated})).expect("JSON"));
    } else {
        if !stdout.is_empty() {
            print!("{stdout}");
        }
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
    }
    Ok(())
}
