use clap::{Parser, Subcommand};
use hostlink::run::JobStream;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(name = "hostlink", version, about = "Pinned managed-host SSH client")]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Inspect legacy snapshots and explicit russh configs without SSH or writes.
    Migration {
        #[command(subcommand)]
        command: MigrationCommand,
    },
    /// Manage the authoritative Hub registry and controller-local Hub settings.
    Hub {
        #[command(subcommand)]
        command: HubCommand,
    },
    /// List authoritative registered hosts without probing by default.
    List {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show registry facts for a registered host without probing SSH.
    Info { host: String },
    /// Verify a registered host using its current Hub pins and SSH identity.
    Verify { host: String },
    /// Create an invitation and a source-pinned bootstrap command.
    Invite {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        ssh_user: Option<String>,
        #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(60..=86400))]
        ttl_seconds: u64,
        /// Create a manual invitation without selecting verified installer artifacts.
        #[arg(long, conflicts_with_all = ["ssh_user", "installer_url", "installer_sha256", "agent_url", "agent_sha256", "archive_url", "archive_sha256", "version", "target", "bootstrap_hub_ca_cert"])]
        token_only: bool,
        #[arg(long)]
        installer_url: Option<String>,
        #[arg(long)]
        installer_sha256: Option<String>,
        #[arg(long)]
        agent_url: Option<String>,
        #[arg(long)]
        agent_sha256: Option<String>,
        #[arg(long)]
        archive_url: Option<String>,
        #[arg(long)]
        archive_sha256: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        target: Option<String>,
        /// PEM CA path available on the target, passed only to the Linux bootstrap and enrollment.
        #[arg(long)]
        bootstrap_hub_ca_cert: Option<PathBuf>,
    },
    /// Change a host's display-only label.
    DisplayName { host: String, display_name: String },
    /// Revoke new managed access; does not uninstall the Agent or terminate existing sessions.
    Remove {
        host: String,
        #[arg(long)]
        yes: bool,
    },
    /// Establish and close a pinned authenticated SSH connection.
    Check {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
    },
    /// Forward a loopback TCP port to a target reachable from the SSH host.
    Forward {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long, value_parser = parse_socket_addr)]
        listen: SocketAddr,
        #[arg(long, value_parser = parse_socket_addr)]
        target: SocketAddr,
    },
    /// Forward local RDP to 127.0.0.1:3389 on the SSH host.
    Rdp {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long, default_value_t = 13389, value_parser = clap::value_parser!(u16).range(1..))]
        listen_port: u16,
    },
    /// Probe TCP reachability from the SSH host through a direct-tcpip channel.
    Probe {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long, value_parser = parse_socket_addr)]
        target: SocketAddr,
        #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u64).range(1..=60000))]
        timeout_ms: u64,
    },
    /// Execute a single remote shell command with binary stdin/out and exact exit status.
    Exec {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        command: String,
        /// Path to a bounded binary stdin payload; "-" reads controller stdin.
        #[arg(long)]
        stdin_file: Option<String>,
    },
    /// Create a new remote file using authenticated SFTP (never overwrite).
    Upload {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    /// Download an SFTP file to a new local file (never overwrite).
    Download {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
    /// Inspect or reattach to an Agent-owned durable job.
    Jobs {
        #[command(subcommand)]
        command: JobCommand,
    },
}

#[derive(Subcommand)]
pub(super) enum MigrationCommand {
    /// Produce a redacted, offline per-host readiness report.
    Preflight {
        #[arg(long)]
        old_hub: PathBuf,
        #[arg(long)]
        old_controller: PathBuf,
        #[arg(long)]
        old_agent: PathBuf,
        #[arg(long)]
        new_agent: PathBuf,
        #[arg(long)]
        new_host: PathBuf,
    },
}

#[derive(Subcommand)]
pub(super) enum JobCommand {
    /// List one page (32 jobs) owned by this controller, across all statuses.
    List {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=128))]
        page: u32,
        /// Optional native Apalis status.
        #[arg(long, value_parser = ["Pending", "Queued", "Running", "Done", "Failed", "Killed"])]
        status: Option<String>,
    },
    /// Upload, seal and enqueue a source-pinned binary with exact argv.
    Run {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        binary: PathBuf,
        /// Caller-owned canonical ULID; generated and printed before connecting when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Stream raw output and return the actual process exit code.
        #[arg(long)]
        wait: bool,
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Read the persisted state of a durable job.
    Status {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        id: String,
    },
    /// Request cancellation of one owned Agent job; read status to confirm termination.
    Cancel {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        id: String,
    },
    /// Read one raw output stream from a persisted byte offset.
    Logs {
        #[arg(long, group = "host_selection", required_unless_present = "host")]
        config: Option<PathBuf>,
        #[arg(long, group = "host_selection", required_unless_present = "config")]
        host: Option<String>,
        #[arg(long)]
        id: String,
        #[arg(long, value_parser = parse_stream)]
        stream: JobStream,
        #[arg(long)]
        offset: u64,
    },
}

#[derive(Subcommand)]
pub(super) enum HubCommand {
    /// Save controller-local Hub URL, token source, SSH user and pinned identity paths.
    Configure {
        #[arg(long)]
        hub_url: String,
        /// Additional private Hub CA in PEM format; certificate validation remains enabled.
        #[arg(long)]
        hub_ca_cert: Option<PathBuf>,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        ssh_user: String,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        gateway_identity: PathBuf,
        /// Exact Hub route host:port selected as primary when /v2/info lists multiple gateways.
        #[arg(long)]
        preferred_gateway: Option<String>,
    },
    /// Display non-secret controller-local Hub settings.
    Show,
    /// Check Hub operator API reachability and bearer authorization only.
    Check,
}

pub(super) fn parse_stream(value: &str) -> Result<JobStream, String> {
    match value {
        "stdout" => Ok(JobStream::Stdout),
        "stderr" => Ok(JobStream::Stderr),
        _ => Err("stream must be stdout or stderr".into()),
    }
}

pub(super) fn parse_socket_addr(value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| "expected an IP:PORT socket address".into())
}
