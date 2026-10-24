use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// Bind one controller-local environment variable into the child secret environment.
    #[arg(long = "secret-env", value_name = "KEY=SOURCE_ENV")]
    pub(crate) secret_env: Vec<String>,
    /// Controller-local stdin source; use "-" to read one bounded payload from stdin.
    #[arg(long, value_name = "PATH")]
    pub(crate) stdin_file: Option<PathBuf>,
    /// Declare one logical result artifact as NAME=MAX_BYTES (repeatable).
    #[arg(long = "result", value_name = "NAME=MAX_BYTES")]
    pub(crate) results: Vec<String>,
    /// Local directory for declared result artifacts; required with --result.
    #[arg(long, value_name = "DIR")]
    pub(crate) result_dir: Option<PathBuf>,
    #[arg(long, default_value_t = hostlink_protocol::DEFAULT_EXEC_TIMEOUT_MS)]
    pub(crate) timeout_ms: u64,
    #[arg(required = true, trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    super::super::transport::exec(
        args.name,
        args.cwd,
        super::super::transport::ExecOptions {
            env: args.env,
            secret_env: args.secret_env,
            stdin_file: args.stdin_file,
            results: args.results,
            result_dir: args.result_dir,
            timeout_ms: args.timeout_ms,
        },
        args.command,
    )
    .await
}
