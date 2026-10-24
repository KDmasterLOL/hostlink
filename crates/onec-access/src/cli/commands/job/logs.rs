use clap::Args as ClapArgs;
use onec_agent_protocol::AgentResponseKind;
use serde_json::json;
#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    pub(crate) job_id: String,
    #[arg(long, default_value_t = 64 * 1024)]
    pub(crate) tail_bytes: u64,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    let Args {
        name,
        job_id,
        tail_bytes,
        json,
    } = args;
    let response = super::super::super::jobs::client(&name)
        .await?
        .job_logs(job_id, tail_bytes)
        .await?;
    let AgentResponseKind::JobLogs {
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
            "remote agent returned a non-job-logs response".to_owned(),
        ));
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "job_id": job_id,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "stdout_storage_truncated": stdout_storage_truncated,
                "stderr_storage_truncated": stderr_storage_truncated,
            }))
            .expect("job log JSON serialization should succeed")
        );
    } else {
        if stdout_storage_truncated {
            eprintln!("[job logs] older durable stdout was discarded by the storage bound");
        } else if stdout_truncated {
            eprintln!("[job logs] stdout truncated to the requested tail");
        }
        if stderr_storage_truncated {
            eprintln!("[job logs] older durable stderr was discarded by the storage bound");
        } else if stderr_truncated {
            eprintln!("[job logs] stderr truncated to the requested tail");
        }
        if !stdout.is_empty() {
            print!("{stdout}");
        }
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
    }
    Ok(())
}
