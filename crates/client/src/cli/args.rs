use crate::cli::invite::Target;
use clap::{Args, Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "hostlink",
    version,
    about = "Pinned managed-host SSH client",
    after_help = "Durable jobs are managed through the Agent's Apalis board UI/API. Automatic crash recovery may repeat job side effects."
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

/// Exactly one SSH destination source, enforced by clap before command execution.
#[derive(Args)]
#[group(id = "host_selection", required = true, multiple = false)]
pub(super) struct HostTarget {
    #[arg(long)]
    pub(super) config: Option<PathBuf>,
    #[arg(long)]
    pub(super) host: Option<String>,
}

/// Inputs of one invitation, parsed and checked by clap before any Hub or GitHub I/O.
#[derive(Args)]
pub(super) struct InviteArgs {
    #[arg(value_name = "NAME", conflicts_with = "legacy_name", required_unless_present_any = ["token_only", "legacy_name"])]
    pub(super) name: Option<String>,
    /// Legacy spelling for the machine name.
    #[arg(long = "name", conflicts_with = "name")]
    pub(super) legacy_name: Option<String>,
    /// SSH protocol login, not the target OS account; must match the Controller Hub config ssh_user.
    #[arg(long)]
    pub(super) ssh_user: Option<String>,
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(60..=86400))]
    pub(super) ttl_seconds: u64,
    /// Create a manual Hub invitation without selecting a GitHub binary.
    #[arg(long, conflicts_with_all = ["ssh_user", "version", "target", "os", "bootstrap_hub_ca_cert", "gateway_index"])]
    pub(super) token_only: bool,
    #[arg(long)]
    pub(super) version: Option<String>,
    #[arg(long, required_unless_present_any = ["token_only", "os"], conflicts_with = "os", value_parser = parse_target)]
    pub(super) target: Option<Target>,
    /// Target operating-system family; the target chooses its compatible binary.
    #[arg(long, value_parser = ["windows", "linux"], conflicts_with = "target")]
    pub(super) os: Option<String>,
    /// Zero-based index in the Hub-approved gateway list for Agent installation.
    #[arg(long)]
    pub(super) gateway_index: Option<usize>,
    /// PEM CA path available on the target during enrollment.
    #[arg(long)]
    pub(super) bootstrap_hub_ca_cert: Option<PathBuf>,
    /// Explicitly authorize replacement of lost SSH keys for this full existing ID.
    /// The target also requires typed confirmation; machine ID, port and jobs remain.
    #[arg(long, conflicts_with = "token_only")]
    pub(super) replace_identity: Option<hostlink_hub::MachineId>,
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
    /// Create an invitation using public KDmasterLOL/hostlink GitHub Releases.
    Invite(InviteArgs),
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
        #[command(flatten)]
        host_target: HostTarget,
    },
    /// Open an interactive terminal on a registered host over pinned SSH.
    Ssh {
        /// Registered Hub host name; omit only when using a direct HostSpec config.
        #[arg(required_unless_present = "config")]
        host: Option<String>,
        /// Direct pinned HostSpec JSON, or Hub settings path when HOST is supplied.
        #[arg(long, conflicts_with = "host")]
        config: Option<PathBuf>,
    },
    /// Forward a loopback TCP port to a target reachable from the SSH host.
    Forward {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long, value_parser = parse_socket_addr)]
        listen: SocketAddr,
        #[arg(long, value_parser = parse_socket_addr)]
        target: SocketAddr,
    },
    /// Forward local RDP to 127.0.0.1:3389 on the SSH host.
    Rdp {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long, default_value_t = 13389, value_parser = clap::value_parser!(u16).range(1..))]
        listen_port: u16,
    },
    /// Probe TCP reachability from the SSH host through a direct-tcpip channel.
    Probe {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long, value_parser = parse_socket_addr)]
        target: SocketAddr,
        #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u64).range(1..=60000))]
        timeout_ms: u64,
    },
    /// Execute a single remote shell command with binary stdin/out and exact exit status.
    Exec {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long)]
        detach: bool,
        /// Allow trusted child processes to leave the Windows job; HostLink cannot terminate escaped descendants.
        #[arg(long, conflicts_with = "detach")]
        allow_child_breakaway: bool,
        /// Total foreground SSH exec deadline in seconds (1..=600); cannot be used with --detach.
        #[arg(long, conflicts_with = "detach", value_parser = clap::value_parser!(u64).range(1..=600))]
        exec_timeout_seconds: Option<u64>,
        /// Maximum Agent command runtime in seconds (1..=14400); requires --detach.
        #[arg(long, requires = "detach", value_parser = clap::value_parser!(u64).range(1..=14400))]
        timeout_seconds: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        board_port: Option<u16>,
        /// Target operating system when using a direct --config target; Hub hosts use registry OS.
        #[arg(long, value_parser = ["linux", "windows"])]
        os: Option<String>,
        #[arg(long)]
        command: String,
        /// Path to a bounded binary stdin payload; "-" reads controller stdin.
        #[arg(long)]
        stdin_file: Option<String>,
    },
    /// Read status for an Agent-local Apalis job.
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Create a new remote file using authenticated SFTP (never overwrite).
    Upload {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    /// Download an SFTP file to a new local file (never overwrite).
    Download {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
}

#[derive(Subcommand)]
pub(super) enum JobCommand {
    Status {
        #[command(flatten)]
        host_target: HostTarget,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        board_port: u16,
        job_id: String,
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

pub(super) fn parse_socket_addr(value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| "expected an IP:PORT socket address".into())
}

fn parse_target(raw: &str) -> Result<Target, String> {
    Target::parse(raw).map_err(|error| error.to_string())
}
