use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    /// Hub-managed target; falls back to ONEC_ACCESS_TARGET when omitted.
    #[arg(long)]
    pub(crate) target: Option<String>,
    /// Maximum effect required by this invocation: read-only, run-owned, or disposable.
    #[arg(long, value_enum)]
    pub(crate) required_effect: crate::cli::values::TargetEffect,
    /// Remote working directory for the child.
    #[arg(long)]
    pub(crate) cwd: Option<String>,
    /// Non-secret remote environment overlay as KEY=VALUE (repeatable).
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// Bind a controller-local variable into the child secret environment.
    #[arg(long = "secret-env", value_name = "KEY=SOURCE_ENV")]
    pub(crate) secret_env: Vec<String>,
    /// Stage a local file from the named controller environment variable and rewrite it to a remote path.
    #[arg(long = "map-file-env", value_name = "KEY")]
    pub(crate) map_file_env: Vec<String>,
    /// Outer remote execution emergency ceiling. Native test timeout/scheduling belongs to Nextest.
    #[arg(long, default_value_t = onec_agent_protocol::MAX_EXEC_TIMEOUT_MS)]
    pub(crate) timeout_ms: u64,
    /// Local executable followed by exact child arguments.
    #[arg(required = true, trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<i32> {
    super::super::transport::run_local(
        args.target,
        super::super::transport::RunLocalOptions {
            required_effect: args.required_effect.into(),
            cwd: args.cwd,
            ordinary_env: args.env,
            secret_bindings: args.secret_env,
            mapped_env: args.map_file_env,
            timeout_ms: args.timeout_ms,
        },
        args.command,
    )
    .await
}
