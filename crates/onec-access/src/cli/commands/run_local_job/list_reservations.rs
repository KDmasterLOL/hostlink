use crate::cli::mutable_lease;
use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) target: String,
    #[arg(long)]
    pub(crate) json: bool,
}

pub(super) async fn run(args: Args) -> onec_access::AppResult<()> {
    let Args { target, json } = args;
    let machine_id = controller::resolve_machine_id(&target).await?;
    let reservations = mutable_lease::list_durable_run_local_reservations(
        &controller::controller_data_root()?,
        &machine_id,
    )?;
    if json {
        let items = reservations
            .iter()
            .map(|(run_id, job_id)| serde_json::json!({"run_id": run_id, "job_id": job_id}))
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&items).expect("JSON"));
    } else if reservations.is_empty() {
        println!("No durable run-local reservations for {machine_id}");
    } else {
        for (run_id, job_id) in reservations {
            println!(
                "run_id={run_id} job_id={}",
                job_id.as_deref().unwrap_or("pending")
            );
        }
    }
    Ok(())
}
