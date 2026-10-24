use clap::{Args as ClapArgs, Subcommand};

pub(crate) mod attest;
pub(crate) mod cancel;
pub(crate) mod cleanup;
pub(crate) mod list_reservations;
pub(crate) mod logs;
pub(crate) mod observe_invocation;
pub(crate) mod recover_attest;
pub(crate) mod recover_invocation;
pub(crate) mod results;
pub(crate) mod start;
pub(crate) mod status;
pub(crate) mod verify_invocation_logs;
pub(crate) mod verify_invocation_result;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Start(start::Args),
    Status(status::Args),
    Logs(logs::Args),
    Cancel(cancel::Args),
    Results(results::Args),
    Attest(attest::Args),
    RecoverAttest(recover_attest::Args),
    ObserveInvocation(observe_invocation::Args),
    RecoverInvocation(recover_invocation::Args),
    VerifyInvocationLogs(verify_invocation_logs::Args),
    VerifyInvocationResult(verify_invocation_result::Args),
    Cleanup(cleanup::Args),
    ListReservations(list_reservations::Args),
}

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(super) async fn run(args: Args) -> hostlink_access::AppResult<()> {
    match args.command {
        Command::Start(args) => start::run(args).await,
        Command::Status(args) => status::run(args).await,
        Command::Logs(args) => logs::run(args).await,
        Command::Cancel(args) => cancel::run(args).await,
        Command::Results(args) => results::run(args).await,
        Command::Attest(args) => attest::run(args).await,
        Command::RecoverAttest(args) => recover_attest::run(args).await,
        Command::ObserveInvocation(args) => observe_invocation::run(args).await,
        Command::RecoverInvocation(args) => recover_invocation::run(args).await,
        Command::VerifyInvocationLogs(args) => verify_invocation_logs::run(args).await,
        Command::VerifyInvocationResult(args) => verify_invocation_result::run(args).await,
        Command::Cleanup(args) => cleanup::run(args).await,
        Command::ListReservations(args) => list_reservations::run(args).await,
    }
}
