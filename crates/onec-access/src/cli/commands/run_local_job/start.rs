use crate::cli::run_local_job as controller;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    pub(crate) target: Option<String>,
    #[arg(long, value_enum)]
    pub(crate) required_effect: crate::cli::values::TargetEffect,
    /// Explicitly request Agent-native invocation observation for this durable job.
    #[arg(long, value_enum)]
    pub(crate) native_effect: Option<crate::cli::values::NativeExecutionEffect>,
    /// Explicitly request an Agent-pinned complete native suite policy from this JSON file.
    #[arg(long, value_name = "JSON")]
    pub(crate) native_suite_policy: Option<PathBuf>,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    #[arg(long = "secret-env", value_name = "KEY=SOURCE_ENV")]
    pub(crate) secret_env: Vec<String>,
    #[arg(long = "map-file-env", value_name = "KEY")]
    pub(crate) map_file_env: Vec<String>,
    #[arg(long = "result", value_name = "NAME=MAX_BYTES")]
    pub(crate) results: Vec<String>,
    #[arg(long)]
    pub(crate) json: bool,
    /// Require the exact candidate to already exist in the Agent cache; never upload it.
    #[arg(long)]
    pub(crate) require_cached_candidate: bool,
    #[arg(required = true, trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        target,
        required_effect,
        native_effect,
        native_suite_policy,
        cwd,
        env,
        secret_env,
        map_file_env,
        results,
        json,
        require_cached_candidate,
        command,
    } = args;
    let (run_id, job) = controller::start(
        controller::StartOptions {
            target,
            effect: required_effect.into(),
            native_effect: native_effect.map(Into::into),
            native_suite_policy,
            cwd,
            ordinary_env: env,
            secret_bindings: secret_env,
            mapped_env: map_file_env,
            result_args: results,
            require_cached_candidate,
        },
        command,
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&job).expect("JSON"));
    } else {
        println!("run_id={run_id}\njob_id={}", job.job_id);
    }
    Ok(())
}
