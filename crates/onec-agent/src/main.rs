use clap::{Args, Parser, Subcommand};
use hostlink_agent::embedded_ssh::preflight_embedded_ssh;
use hostlink_agent::{
    AgentConfig, AgentPackageUpdateRequest, DirectPackageUpdateRequest, PrepareEnrollmentRequest,
    RuntimeUpdateOutcome, RuntimeUpdatePreflightOutcome, install_service, post_enrollment_json,
    preflight_runtime_update, prepare_enrollment, probe_tunnel, run_job_worker, run_service,
    run_sshd_host, run_with_tunnel, serve, service_status, start_service, stop_service,
    uninstall_service, update_agent_package, update_direct_package,
};
use std::io;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "hostlink-agent",
    version,
    about = "Outbound managed remote-control agent for HostLink"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate agent configuration and print the resolved control endpoint.
    Check(ConfigArgs),
    /// Start only the loopback control endpoint.
    Serve(ConfigArgs),
    /// Supervise the configured outbound SSH reverse tunnel.
    Run(ConfigArgs),
    /// Verify the configured tunnel for a bounded interval and exit.
    ProbeTunnel(ProbeTunnelArgs),
    /// Install the Windows service and optionally start it immediately.
    InstallService(InstallServiceArgs),
    /// Start the installed Windows service.
    StartService,
    /// Stop the installed Windows service.
    StopService,
    /// Print the installed Windows service state as JSON.
    ServiceStatus,
    /// Uninstall the Windows service, optionally stopping it first.
    UninstallService(UninstallServiceArgs),
    /// Internal Windows SCM entrypoint.
    #[command(hide = true)]
    Service(ConfigArgs),
    /// Internal persistent-job worker entrypoint.
    #[command(name = "__job-worker", hide = true)]
    JobWorker(JobWorkerArgs),
    /// Internal Windows host for toolkit-managed user-mode sshd.
    #[command(name = "__sshd-host", hide = true)]
    SshdHost(SshdHostArgs),
    /// Internal exact managed-runtime updater entrypoint.
    #[command(name = "__self-update", hide = true)]
    SelfUpdate(SelfUpdateArgs),
    /// Internal fresh-install enrollment transport.
    #[command(name = "__enroll-http", hide = true)]
    EnrollHttp(EnrollHttpArgs),
    /// Internal fresh user-scope enrollment and candidate configuration builder.
    #[command(name = "__prepare-enrollment", hide = true)]
    PrepareEnrollment(PrepareEnrollmentArgs),
    /// Internal embedded-SSH candidate acceptance probe.
    #[command(name = "__embedded-ssh-preflight", hide = true)]
    EmbeddedSshPreflight(EmbeddedSshPreflightArgs),
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// Path to agent.json.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct ProbeTunnelArgs {
    #[command(flatten)]
    target: ConfigArgs,
    /// Verification interval in seconds.
    #[arg(
        long,
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..=300),
        value_name = "SECONDS"
    )]
    seconds: u64,
}

#[derive(Debug, Args)]
struct InstallServiceArgs {
    #[command(flatten)]
    target: ConfigArgs,
    /// Start the service after installation.
    #[arg(long)]
    start: bool,
}

#[derive(Debug, Args)]
struct UninstallServiceArgs {
    /// Stop the service before uninstalling it.
    #[arg(long)]
    stop: bool,
}

#[derive(Debug, Args)]
struct JobWorkerArgs {
    #[arg(long, value_name = "PATH")]
    job_dir: PathBuf,
}

#[derive(Debug, Args)]
struct SshdHostArgs {
    #[arg(long, value_name = "PATH")]
    program: PathBuf,
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "NAME")]
    start_event: String,
}

#[derive(Debug, Args)]
struct SelfUpdateArgs {
    #[arg(long, value_name = "PATH")]
    root: PathBuf,
    /// Exact externally selected HTTPS ZIP URL; selects the direct package route.
    #[arg(long, value_name = "HTTPS_URL", conflicts_with = "archive_file")]
    archive_url: Option<String>,
    /// Absolute staged ZIP path inside the toolkit root; selects the local direct route.
    #[arg(long, value_name = "PATH", conflicts_with = "archive_url")]
    archive_file: Option<PathBuf>,
    /// Trusted SHA-256 of the exact archive bytes; required with archive_url.
    #[arg(long, value_name = "SHA256")]
    archive_sha256: Option<String>,
    /// Ordinary package version selected with the direct archive.
    #[arg(long, value_name = "VERSION")]
    package_version: Option<String>,
    /// Supported Rust target triple selected with the direct archive.
    #[arg(long, value_name = "TRIPLE")]
    target: Option<String>,
    /// Check durable-job blockers without downloading or replacing runtime files.
    #[arg(long)]
    preflight: bool,
    /// Select the independent HostLink Agent-only archive format.
    #[arg(long)]
    agent_only: bool,
}

impl SelfUpdateArgs {
    fn validate_mode(&self) -> io::Result<()> {
        let has_source = self.archive_url.is_some() || self.archive_file.is_some();
        let direct_metadata_count = [
            self.archive_sha256.is_some(),
            self.package_version.is_some(),
            self.target.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        let direct = has_source || direct_metadata_count != 0;
        if self.agent_only && !direct {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--agent-only requires an exact archive, SHA-256, version, and target",
            ));
        }
        if self.preflight && (direct || self.agent_only) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--preflight cannot be combined with update selection arguments",
            ));
        }
        if direct
            && (direct_metadata_count != 3
                || self.archive_url.is_some() == self.archive_file.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct update requires exactly one of --archive-url or --archive-file, plus --archive-sha256, --package-version, and --target",
            ));
        }
        if !direct && !self.preflight {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "automatic latest updates are retired; provide --archive-url or --archive-file with --archive-sha256, --package-version, and --target",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
struct EnrollHttpArgs {
    #[arg(long)]
    url: String,
    #[arg(long, value_name = "PATH")]
    token_file: PathBuf,
    #[arg(long, value_name = "PATH")]
    body_file: PathBuf,
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct PrepareEnrollmentArgs {
    #[arg(long, value_name = "HTTPS_URL")]
    hub_url: String,
    #[arg(long, value_name = "PATH")]
    token_file: PathBuf,
    #[arg(long, value_name = "PATH")]
    state_dir: PathBuf,
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
}

#[derive(Debug, Args)]
struct EmbeddedSshPreflightArgs {
    #[command(flatten)]
    target: ConfigArgs,
    #[arg(long, value_name = "PATH")]
    host_public_key: PathBuf,
    #[arg(long, value_name = "PATH")]
    identity: PathBuf,
    #[arg(long, value_name = "PATH")]
    scratch_dir: PathBuf,
}

fn main() {
    let command = Cli::parse().command;
    if let Command::SshdHost(args) = command {
        match run_sshd_host(&args.program, &args.config, &args.start_event) {
            Ok(exit_code) => std::process::exit(exit_code as i32),
            Err(error) => {
                eprintln!("hostlink-agent sshd host: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Command::EmbeddedSshPreflight(args) = command {
        if let Err(error) = run_embedded_ssh_preflight_cli(args) {
            eprintln!("hostlink-agent: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = run(command) {
        eprintln!("hostlink-agent: {error}");
        std::process::exit(1);
    }
}

fn run_embedded_ssh_preflight_cli(args: EmbeddedSshPreflightArgs) -> io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?
        .block_on(run_embedded_ssh_preflight_command(args))
}

async fn run_embedded_ssh_preflight_command(args: EmbeddedSshPreflightArgs) -> io::Result<()> {
    let config = AgentConfig::load(&args.target.config)?;
    let embedded = config.embedded_ssh_server().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded SSH preflight requires embedded_ssh_server in agent config",
        )
    })?;
    preflight_embedded_ssh(
        embedded,
        &args.host_public_key,
        &args.identity,
        &args.scratch_dir,
    )
    .await
}

fn run(command: Command) -> io::Result<()> {
    match command {
        Command::JobWorker(args) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?
            .block_on(run_job_worker(args.job_dir)),
        Command::EnrollHttp(args) => {
            post_enrollment_json(&args.url, &args.token_file, &args.body_file, &args.output)
        }
        Command::PrepareEnrollment(args) => prepare_enrollment(PrepareEnrollmentRequest {
            hub_url: args.hub_url,
            token_file: args.token_file,
            state_dir: args.state_dir,
            name: args.name,
        }),
        Command::EmbeddedSshPreflight(_) => {
            unreachable!("embedded SSH preflight is handled at the CLI runtime boundary")
        }
        Command::SelfUpdate(args) => {
            args.validate_mode()?;
            if args.preflight {
                let value = match preflight_runtime_update(&args.root)? {
                    RuntimeUpdatePreflightOutcome::Ready => {
                        serde_json::json!({"status":"ready"})
                    }
                    RuntimeUpdatePreflightOutcome::DeferredActiveJobs { job_ids } => {
                        serde_json::json!({"status":"deferred_active_jobs","job_ids":job_ids})
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string(&value).expect("managed update preflight serializes")
                );
                return Ok(());
            }
            let archive_sha256 = args.archive_sha256.expect("validated direct mode");
            let package_version = args.package_version.expect("validated direct mode");
            let target = args.target.expect("validated direct mode");
            let outcome = if args.agent_only {
                update_agent_package(&AgentPackageUpdateRequest {
                    root: args.root,
                    archive_url: args.archive_url,
                    archive_file: args.archive_file,
                    archive_sha256,
                    package_version,
                    target,
                })?
            } else {
                update_direct_package(&DirectPackageUpdateRequest {
                    root: args.root,
                    archive_url: args.archive_url,
                    archive_file: args.archive_file,
                    archive_sha256,
                    package_version,
                    target,
                })?
            };
            let value = match outcome {
                RuntimeUpdateOutcome::DeferredActiveJobs { job_ids } => {
                    serde_json::json!({"status":"deferred_active_jobs","job_ids":job_ids})
                }
                RuntimeUpdateOutcome::DirectUpToDate {
                    package_version,
                    archive_sha256,
                } => serde_json::json!({
                    "status":"up_to_date",
                    "package_version":package_version,
                    "archive_sha256":archive_sha256
                }),
                RuntimeUpdateOutcome::DirectUpdated {
                    package_version,
                    archive_sha256,
                } => serde_json::json!({
                    "status":"updated",
                    "package_version":package_version,
                    "archive_sha256":archive_sha256
                }),
            };
            println!(
                "{}",
                serde_json::to_string(&value).expect("runtime update outcome serializes")
            );
            Ok(())
        }
        Command::SshdHost(_) => unreachable!("sshd host is handled before ordinary CLI dispatch"),
        Command::StartService => print_service_status(start_service()?),
        Command::StopService => print_service_status(stop_service()?),
        Command::ServiceStatus => print_service_status(service_status()?),
        Command::UninstallService(args) => uninstall_service(args.stop),
        Command::InstallService(args) => {
            AgentConfig::load(&args.target.config)?;
            install_service(&args.target.config, args.start)
        }
        Command::Service(args) => run_service(args.config),
        Command::Check(args) => {
            let config = load_runtime_config(&args.config)?;
            let socket = config.listen();
            println!(
                "{}",
                serde_json::json!({
                    "name": config.name(),
                    "listen": socket.to_string(),
                    "ssh": config.ssh().is_some(),
                })
            );
            Ok(())
        }
        Command::Serve(args) => {
            let config = load_runtime_config(&args.config)?;
            serve(&config)
        }
        Command::Run(args) => {
            let config = load_runtime_config(&args.config)?;
            run_with_tunnel(&config)
        }
        Command::ProbeTunnel(args) => {
            let config = load_runtime_config(&args.target.config)?;
            probe_tunnel(&config, std::time::Duration::from_secs(args.seconds))
        }
    }
}

fn load_runtime_config(path: &std::path::Path) -> io::Result<AgentConfig> {
    let config = AgentConfig::load(path)?;
    config.apply_process_environment()?;
    Ok(config)
}

fn print_service_status(status: hostlink_agent::ServiceRuntimeStatus) -> io::Result<()> {
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "installed": status.installed,
            "state": status.state,
            "process_id": status.process_id,
        }))
        .expect("service status serializes")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn root_help_uses_standard_clap_layout_and_hides_internal_commands() {
        let help = Cli::command()
            .try_get_matches_from(["hostlink-agent", "--help"])
            .expect_err("help exits through DisplayHelp")
            .to_string();
        assert!(help.contains("Usage: hostlink-agent <COMMAND>"));
        assert!(help.contains("Commands:"));
        assert!(help.contains("Options:"));
        assert!(help.contains("probe-tunnel"));
        assert!(help.contains("install-service"));
        assert!(!help.contains("__job-worker"));
        assert!(!help.contains("__sshd-host"));
        assert!(!help.contains("__self-update"));
        assert!(!help.contains("__enroll-http"));
        assert!(!help.contains("__prepare-enrollment"));
        assert!(!help.contains("__embedded-ssh-preflight"));
        assert!(!help.contains("Internal Windows SCM entrypoint"));
    }

    #[test]
    fn probe_tunnel_seconds_are_validated_by_clap() {
        for seconds in ["1", "300"] {
            Cli::try_parse_from([
                "hostlink-agent",
                "probe-tunnel",
                "--config",
                "agent.json",
                "--seconds",
                seconds,
            ])
            .expect("boundary value must parse");
        }
        for seconds in ["0", "301", "not-a-number"] {
            assert!(
                Cli::try_parse_from([
                    "hostlink-agent",
                    "probe-tunnel",
                    "--config",
                    "agent.json",
                    "--seconds",
                    seconds,
                ])
                .is_err(),
                "invalid seconds value parsed: {seconds}"
            );
        }
    }

    #[test]
    fn internal_commands_remain_parseable() {
        assert!(
            Cli::try_parse_from(["hostlink-agent", "service", "--config", "agent.json"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["hostlink-agent", "__job-worker", "--job-dir", "job"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__sshd-host",
                "--program",
                "sshd.exe",
                "--config",
                "sshd_config",
                "--start-event",
                "Local\\onec_toolkit_sshd_start_1_1",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__self-update",
                "--root",
                "toolkit-root",
                "--preflight",
            ])
            .is_ok()
        );
        let no_selection =
            Cli::try_parse_from(["hostlink-agent", "__self-update", "--root", "toolkit-root"])
                .expect("empty selection parses before semantic validation");
        let Command::SelfUpdate(no_selection) = no_selection.command else {
            panic!("expected self-update command");
        };
        let error = no_selection.validate_mode().expect_err("latest is retired");
        assert!(
            error
                .to_string()
                .contains("automatic latest updates are retired")
        );

        let direct = Cli::try_parse_from([
            "hostlink-agent",
            "__self-update",
            "--root",
            "toolkit-root",
            "--archive-url",
            "https://packages.example.test/onec-toolkit.zip",
            "--archive-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--package-version",
            "1.2.3",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .expect("direct package arguments");
        let Command::SelfUpdate(direct) = direct.command else {
            panic!("expected self-update command");
        };
        direct.validate_mode().expect("direct mode");

        let local = Cli::try_parse_from([
            "hostlink-agent",
            "__self-update",
            "--root",
            "C:\\ToolKit",
            "--archive-file",
            "C:\\ToolKit\\staging\\package.zip",
            "--archive-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--package-version",
            "1.2.3",
            "--target",
            "x86_64-pc-windows-msvc",
        ])
        .expect("local package arguments");
        let Command::SelfUpdate(local) = local.command else {
            panic!("expected self-update command");
        };
        local.validate_mode().expect("local direct mode");

        let agent_only = Cli::try_parse_from([
            "hostlink-agent",
            "__self-update",
            "--root",
            "agent-root",
            "--agent-only",
            "--archive-file",
            "agent-root/package.zip",
            "--archive-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--package-version",
            "1.2.3",
            "--target",
            "x86_64-unknown-linux-gnu",
        ])
        .expect("Agent-only arguments");
        let Command::SelfUpdate(agent_only) = agent_only.command else {
            panic!("expected self-update command")
        };
        agent_only.validate_mode().expect("valid Agent-only mode");

        let malformed = Cli::try_parse_from([
            "hostlink-agent",
            "__self-update",
            "--root",
            "agent-root",
            "--agent-only",
        ])
        .expect("malformed selection parses before semantic validation");
        let Command::SelfUpdate(malformed) = malformed.command else {
            panic!("expected self-update command")
        };
        assert!(malformed.validate_mode().is_err());

        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__enroll-http",
                "--url",
                "https://hub.example.test/v1/enroll",
                "--token-file",
                "token.txt",
                "--body-file",
                "body.json",
                "--output",
                "response.json",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__prepare-enrollment",
                "--hub-url",
                "https://hub.example",
                "--token-file",
                "/private/invite.token",
                "--state-dir",
                "/tmp/agent-state"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__prepare-enrollment",
                "--hub-url",
                "https://hub.example",
                "--enroll-token",
                "plaintext-secret",
                "--state-dir",
                "/tmp/agent-state"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink-agent",
                "__embedded-ssh-preflight",
                "--config",
                "agent.json",
                "--host-public-key",
                "ssh_host_ed25519_key.pub",
                "--identity",
                "id_ed25519",
                "--scratch-dir",
                "scratch",
            ])
            .is_ok()
        );
    }
}
