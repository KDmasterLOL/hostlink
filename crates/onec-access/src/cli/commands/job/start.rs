use clap::Args as ClapArgs;
use hostlink_protocol::AgentResponseKind;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// Bind one controller-local environment variable into the durable child secret environment.
    #[arg(long = "secret-env", value_name = "KEY=SOURCE_ENV")]
    pub(crate) secret_env: Vec<String>,
    /// Controller-local stdin source; use "-" to read one bounded payload from stdin.
    #[arg(long, value_name = "PATH")]
    pub(crate) stdin_file: Option<PathBuf>,
    /// Declare one logical result artifact as NAME=MAX_BYTES (repeatable).
    #[arg(long = "result", value_name = "NAME=MAX_BYTES")]
    pub(crate) results: Vec<String>,
    #[arg(long)]
    pub(crate) json: bool,
    #[arg(required = true, trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    let Args {
        name,
        cwd,
        env,
        secret_env,
        stdin_file,
        results,
        json,
        command,
    } = args;
    let mut command = command.into_iter();
    let program = command
        .next()
        .ok_or_else(|| crate::invalid_config("job start requires a program".to_owned()))?;
    let args = command.collect::<Vec<_>>();
    let env = super::super::super::jobs::parse_env(&env)?;
    let secret_env = super::super::super::secrets::resolve_secret_env(&secret_env, &env)?;
    let stdin = super::super::super::input::read_stdin_payload(stdin_file)?;
    let results = super::super::super::jobs::parse_result_specs(&results)?;
    let client = super::super::super::jobs::client(&name).await?;
    let response = client
        .start_job(program)
        .args(args)
        .maybe_cwd(cwd)
        .env(env)
        .secret_env(secret_env)
        .maybe_stdin(stdin)
        .results(results)
        .call()
        .await?;
    let AgentResponseKind::JobStarted { job } = response else {
        return Err(crate::invalid_config(
            "remote agent returned a non-job-started response".to_owned(),
        ));
    };
    if json {
        super::super::super::jobs::print_job(&job, true);
    } else {
        println!("{}", job.job_id);
    }
    Ok(())
}
