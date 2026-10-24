//! One adapter per user-visible command leaf.

use clap::Subcommand;
use onec_access::AppResult;

mod check;
mod configure;
mod display_name;
mod download;
mod exec;
mod forward;
mod info;
pub(crate) mod invite;
pub(crate) mod job;
mod list;
pub(crate) mod migrate_runtime;
mod migration_report;
mod probe;
mod rdp;
mod remove;
mod remove_scoped;
mod run_local;
mod run_local_evidence;
pub(crate) mod run_local_job;
mod show;
mod ssh;
mod sync_ssh;
mod upload;
mod verify;

#[derive(Debug, Subcommand)]
pub(crate) enum AccessCommand {
    /// Save controller connection settings for the hub.
    Configure(configure::Args),
    /// Check hub API access using the configured operator token.
    Check(check::Args),
    /// Show controller configuration without secret values.
    Show(show::Args),
    /// Mint a one-use enrollment token and render the Windows bootstrap command.
    Invite(invite::Args),
    /// Migrate an already-enrolled Windows target to an explicitly pinned runtime package.
    MigrateRuntime(migrate_runtime::Args),
    /// List enrolled hosts and current agent reachability.
    List(list::Args),
    /// Report enrolled targets that still need runtime migration without changing them.
    MigrationReport(migration_report::Args),
    /// Revoke an enrolled host from the hub.
    Remove(remove::Args),
    /// Update a display-only label without changing the stable host identity.
    DisplayName(display_name::Args),
    /// Print live agent status.
    Info(info::Args),
    /// Verify managed-host access and agent identity.
    Verify(verify::Args),
    /// Execute a program through the authenticated agent without shell interpolation.
    Exec(exec::Args),
    /// Run a controller-local executable on one managed host through a verified content cache.
    RunLocal(run_local::Args),
    /// Check integrity and schema of a per-process `run-local` observation.
    RunLocalEvidence(run_local_evidence::Args),
    /// Start or resume one source-exact durable local-candidate run.
    RunLocalJob(run_local_job::Args),
    /// Manage durable onec-agent jobs.
    Job(job::Args),
    /// Probe a TCP endpoint from the managed host.
    Probe(probe::Args),
    /// Upload a file through the managed agent.
    Upload(upload::Args),
    /// Download a file through the managed agent.
    Download(download::Args),
    /// Remove one path only when the agent proves it is contained by the supplied owned root.
    RemoveScoped(remove_scoped::Args),
    /// Forward target RDP to a controller loopback port.
    Rdp(rdp::Args),
    /// Forward one target TCP endpoint to a local listener.
    Forward(forward::Args),
    /// Synchronize strict managed OpenSSH config/known_hosts from the hub inventory.
    SyncSsh(sync_ssh::Args),
    /// Run normal OpenSSH against one managed host.
    Ssh(ssh::Args),
}

pub(super) async fn run(command: AccessCommand) -> AppResult<Option<i32>> {
    match command {
        AccessCommand::Configure(args) => configure::run(args).map(|()| None),
        AccessCommand::Check(args) => check::run(args).await.map(|()| None),
        AccessCommand::Show(args) => show::run(args).map(|()| None),
        AccessCommand::Invite(args) => invite::run(args).await.map(|()| None),
        AccessCommand::MigrateRuntime(args) => migrate_runtime::run(args).await.map(|()| None),
        AccessCommand::List(args) => list::run(args).await.map(|()| None),
        AccessCommand::MigrationReport(args) => migration_report::run(args).await.map(|()| None),
        AccessCommand::Remove(args) => remove::run(args).await.map(|()| None),
        AccessCommand::DisplayName(args) => display_name::run(args).await.map(|()| None),
        AccessCommand::Info(args) => info::run(args).await.map(|()| None),
        AccessCommand::Verify(args) => verify::run(args).await.map(|()| None),
        AccessCommand::Exec(args) => exec::run(args).await.map(|()| None),
        AccessCommand::RunLocal(args) => run_local::run(args).await.map(Some),
        AccessCommand::RunLocalEvidence(args) => run_local_evidence::run(args).map(|()| None),
        AccessCommand::RunLocalJob(args) => run_local_job::run(args).await.map(|()| None),
        AccessCommand::Job(args) => job::run(args).await.map(|()| None),
        AccessCommand::Probe(args) => probe::run(args).await.map(|()| None),
        AccessCommand::Upload(args) => upload::run(args).await.map(|()| None),
        AccessCommand::Download(args) => download::run(args).await.map(|()| None),
        AccessCommand::RemoveScoped(args) => remove_scoped::run(args).await.map(|()| None),
        AccessCommand::Rdp(args) => rdp::run(args).await.map(|()| None),
        AccessCommand::Forward(args) => forward::run(args).await.map(|()| None),
        AccessCommand::SyncSsh(args) => sync_ssh::run(args).await.map(|()| None),
        AccessCommand::Ssh(args) => ssh::run(args).await.map(|()| None),
    }
}
