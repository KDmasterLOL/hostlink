//! CLI for the pinned, pure-russh HostLink controller.

use clap::{Parser, Subcommand};
use hostlink::{
    HostSpec,
    connect::{HostConnection, SshClientError},
    migration::{self, Readiness},
    run::{
        JobSpec, JobStateKind, JobStatus, JobStream, Output, Seal, Start, Status,
        sealed_artifact_name,
    },
};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "hostlink", version, about = "Pinned managed-host SSH client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect legacy snapshots and explicit russh configs without SSH or writes.
    Migration {
        #[command(subcommand)]
        command: MigrationCommand,
    },
    /// Establish and close a pinned authenticated SSH connection.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Execute a single remote shell command with binary stdin/out and exact exit status.
    Exec {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        command: String,
        /// Path to a bounded binary stdin payload; "-" reads controller stdin.
        #[arg(long)]
        stdin_file: Option<String>,
    },
    /// Create a new remote file using authenticated SFTP (never overwrite).
    Upload {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    /// Download an SFTP file to a new local file (never overwrite).
    Download {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
    /// Inspect or reattach to an Agent-owned durable job.
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Upload, seal and run a source-pinned test binary with exact argv.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        /// Caller-owned canonical UUID; a UUID v4 is generated when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Exact test-runner arguments, separated from CLI options with `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
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
enum JobCommand {
    /// Start one durable job request without retrying it.
    Start {
        #[arg(long)]
        config: PathBuf,
        /// Absolute executable path on the managed host.
        #[arg(long)]
        program: String,
        /// Lowercase SHA-256 digest of the executable.
        #[arg(long)]
        source_sha256: String,
        /// Caller-owned canonical UUID; a UUID v4 is generated when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Optional absolute working directory on the managed host.
        #[arg(long)]
        cwd: Option<String>,
        /// Exact argument vector, separated from CLI options with `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Read the persisted state of a durable job.
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Read one raw output stream from a persisted byte offset.
    Output {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, value_parser = parse_stream)]
        stream: JobStream,
        #[arg(long)]
        offset: u64,
    },
}

fn parse_stream(value: &str) -> Result<JobStream, String> {
    match value {
        "stdout" => Ok(JobStream::Stdout),
        "stderr" => Ok(JobStream::Stderr),
        _ => Err("stream must be stdout or stderr".into()),
    }
}

#[tokio::main]
async fn main() {
    let result = run(Cli::parse()).await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("hostlink: {error}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    if let Command::Migration {
        command:
            MigrationCommand::Preflight {
                old_hub,
                old_controller,
                old_agent,
                new_agent,
                new_host,
            },
    } = &cli.command
    {
        let report = migration::preflight(old_hub, old_controller, old_agent, new_agent, new_host)
            .map_err(io::Error::other)?;
        serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
        io::stdout().lock().write_all(b"\n")?;
        return Ok(
            if report
                .hosts
                .iter()
                .any(|host| host.readiness == Readiness::Blocked)
            {
                2
            } else {
                0
            },
        );
    }

    let config_path = match &cli.command {
        Command::Migration { .. } => unreachable!("migration preflight returned above"),
        Command::Check { config }
        | Command::Exec { config, .. }
        | Command::Upload { config, .. }
        | Command::Download { config, .. } => config.clone(),
        Command::Run { config, .. } => config.clone(),
        Command::Job { command } => match command {
            JobCommand::Start { config, .. }
            | JobCommand::Status { config, .. }
            | JobCommand::Output { config, .. } => config.clone(),
        },
    };

    // Validate bounded job input before reading credentials or opening SSH.
    let prepared_job = match &cli.command {
        Command::Job {
            command:
                JobCommand::Start {
                    program,
                    source_sha256,
                    id,
                    cwd,
                    args,
                    ..
                },
        } => {
            let id = id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            validate_job_id(&id)?;
            let spec = JobSpec {
                program: program.clone(),
                args: args.clone(),
                cwd: cwd.clone(),
                source_sha256: source_sha256.clone(),
            };
            validate_job_spec(&spec)?;
            let request = Start { id, spec };
            let encoded = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "op": "start",
                "id": request.id,
                "spec": request.spec,
            }))?;
            if encoded.len() > 64 * 1024 {
                return Err("job request exceeds 64 KiB".into());
            }
            Some(PreparedJob::Start(request))
        }
        Command::Job {
            command: JobCommand::Status { id, .. },
        } => {
            validate_job_id(id)?;
            Some(PreparedJob::Status(Status { id: id.clone() }))
        }
        Command::Job {
            command: JobCommand::Output { id, .. },
        } => {
            validate_job_id(id)?;
            Some(PreparedJob::Output)
        }
        _ => None,
    };

    let prepared_run = match &cli.command {
        Command::Run {
            binary, id, args, ..
        } => {
            let bytes = read_existing_file(binary, MAX_FILE_BYTES)?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let artifact_name = sealed_artifact_name(&digest)?;
            let id = id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            validate_job_id(&id)?;
            if args.iter().any(|arg| arg.as_bytes().contains(&0)) {
                return Err("run arguments must not contain NUL".into());
            }
            let encoded = serde_json::to_vec(args)?;
            if encoded.len() > 64 * 1024 {
                return Err("run arguments exceed 64 KiB".into());
            }
            Some(PreparedRun {
                id,
                bytes,
                digest,
                artifact_name,
                args: args.clone(),
            })
        }
        _ => None,
    };

    if let Some(PreparedJob::Start(request)) = &prepared_job {
        // This precedes HostConnection::connect so a lost start acknowledgement
        // always leaves the caller with the ID needed for a status query.
        eprintln!("hostlink: job id: {}", request.id);
    }
    if let Some(request) = &prepared_run {
        // The ID must be recoverable even if upload, Seal, or start loses its ACK.
        eprintln!("hostlink: job id: {}", request.id);
    }
    let spec = load_host_spec(&config_path)?;
    let mut client = HostConnection::connect(&spec).await?;
    // All errors must still close both the target and optional gateway SSH sessions.
    let operation: Result<i32, Box<dyn Error>> = async {
        match cli.command {
            Command::Migration { .. } => unreachable!("migration preflight returned above"),
            Command::Check { .. } => Ok(0_i32),
            Command::Exec {
                command,
                stdin_file,
                ..
            } => {
                let payload = match stdin_file {
                    Some(path) if path == "-" => read_limited(io::stdin().lock(), MAX_FILE_BYTES)?,
                    Some(path) => read_existing_file(Path::new(&path), MAX_FILE_BYTES)?,
                    None => Vec::new(),
                };
                let response = client.exec(&command, &payload).await?;
                // No HostLink protocol diagnostics on stdout: Cargo/libtest needs exact raw bytes.
                io::stdout().lock().write_all(&response.stdout)?;
                io::stderr().lock().write_all(&response.stderr)?;
                let code = i32::try_from(response.exit_code).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH exit status exceeds process exit range",
                    )
                })?;
                Ok(code)
            }
            Command::Upload { local, remote, .. } => {
                let bytes = read_existing_file(&local, MAX_FILE_BYTES)?;
                client.sftp_upload(&remote, &bytes).await?;
                Ok(0)
            }
            Command::Download { remote, local, .. } => {
                let bytes = client.sftp_download(&remote).await?;
                create_new_output(&local, &bytes)?;
                Ok(0)
            }
            Command::Job { command } => match (command, prepared_job) {
                (JobCommand::Start { .. }, Some(PreparedJob::Start(request))) => {
                    let status = client.job_start(&request).await.map_err(|error| {
                        format!(
                            "job start outcome UNKNOWN for {}: {error}; query with `hostlink job status --config <PATH> --id {}` before any further action",
                            request.id, request.id
                        )
                    })?;
                    write_job_status(&status)?;
                    Ok(0)
                }
                (JobCommand::Status { .. }, Some(PreparedJob::Status(request))) => {
                    let status = client.job_status(&request).await?;
                    write_job_status(&status)?;
                    Ok(0)
                }
                (
                    JobCommand::Output {
                        id,
                        stream,
                        offset,
                        ..
                    },
                    Some(PreparedJob::Output),
                ) => {
                    let output = client
                        .job_output(&Output {
                            id,
                            stream,
                            offset,
                        })
                        .await?;
                    io::stdout().lock().write_all(&output.data)?;
                    eprintln!(
                        "hostlink: job {} state={} code={} next_offset={} eof={}",
                        output.status.id,
                        state_name(&output.status),
                        state_code(&output.status),
                        output.next_offset,
                        output.eof
                    );
                    Ok(0)
                }
                _ => Err("internal job command preparation mismatch".into()),
            },
            Command::Run { .. } => {
                let request = prepared_run.ok_or("internal run command preparation mismatch")?;
                run_test_binary(&mut client, request, &spec, &config_path).await
            }
        }
    }
    .await;
    let cleanup = client.close().await;
    match (operation, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Err(primary), Err(cleanup)) => {
            Err(format!("operation failed: {primary}; SSH cleanup also failed: {cleanup}").into())
        }
    }
}

struct PreparedRun {
    id: String,
    bytes: Vec<u8>,
    digest: String,
    artifact_name: String,
    args: Vec<String>,
}

impl PreparedRun {
    fn seal_request(&self) -> Seal {
        Seal {
            name: self.artifact_name.clone(),
            sha256: self.digest.clone(),
            size: self.bytes.len() as u64,
        }
    }
}

async fn run_test_binary(
    client: &mut HostConnection,
    request: PreparedRun,
    host: &HostSpec,
    config_path: &Path,
) -> Result<i32, Box<dyn Error>> {
    let unknown = |stage: &str, error: &dyn Error| {
        format!(
            "run outcome UNKNOWN during {stage} for {}: {error}; do not rerun or resend start; inspect with `hostlink job status --config {} --id {}` and `hostlink job output --config {} --id {} --stream stdout --offset 0` (repeat for stderr and returned offsets)",
            request.id,
            config_path.display(),
            request.id,
            config_path.display(),
            request.id,
        )
    };

    // Only generic SFTP Failure can mean CREATE_EXCL found an existing file.
    // Every other refusal (permissions, path validation, timeout, transport)
    // remains UNKNOWN and must not be hidden by a Seal request.
    match client
        .sftp_upload(&request.artifact_name, &request.bytes)
        .await
    {
        Ok(()) => {}
        Err(error) if sftp_failure_may_be_existing_file(&error) => {
            // Do not retry or overwrite. The authenticated Seal verifies the
            // complete contents of this exact digest-bound name.
        }
        Err(error) => return Err(unknown("upload", &error).into()),
    }
    let sealed = client
        .job_seal(&request.seal_request())
        .await
        .map_err(|error| unknown("Seal", &error))?;
    if sealed.sha256 != request.digest {
        return Err(unknown(
            "Seal digest verification",
            &io::Error::other("Agent digest mismatch"),
        )
        .into());
    }
    let start = Start {
        id: request.id.clone(),
        spec: JobSpec {
            program: sealed.program,
            args: request.args,
            cwd: None,
            source_sha256: request.digest,
        },
    };
    client
        .job_start(&start)
        .await
        .map_err(|error| unknown("start", &error))?;

    let (mut stdout_offset, mut stderr_offset) = (0_u64, 0_u64);
    let (mut stdout_eof, mut stderr_eof) = (false, false);
    let mut read_failures = 0_u8;
    loop {
        let status = match client
            .job_status(&Status {
                id: request.id.clone(),
            })
            .await
        {
            Ok(status) => status,
            Err(error) if !matches!(error, SshClientError::Invalid(_)) => {
                read_failures += 1;
                if read_failures > 3 {
                    return Err(unknown("status reattach", &error).into());
                }
                *client = HostConnection::connect(host)
                    .await
                    .map_err(|connect_error| unknown("status reconnect", &connect_error))?;
                continue;
            }
            Err(error) => return Err(unknown("status reattach", &error).into()),
        };
        for (stream, offset, eof) in [
            (JobStream::Stdout, &mut stdout_offset, &mut stdout_eof),
            (JobStream::Stderr, &mut stderr_offset, &mut stderr_eof),
        ] {
            let output = match client
                .job_output(&Output {
                    id: request.id.clone(),
                    stream,
                    offset: *offset,
                })
                .await
            {
                Ok(output) => output,
                Err(error) if !matches!(error, SshClientError::Invalid(_)) => {
                    read_failures += 1;
                    if read_failures > 3 {
                        return Err(unknown("output reattach", &error).into());
                    }
                    *client = HostConnection::connect(host)
                        .await
                        .map_err(|connect_error| unknown("output reconnect", &connect_error))?;
                    continue;
                }
                Err(error) => return Err(unknown("output reattach", &error).into()),
            };
            *offset = output.next_offset;
            *eof = output.eof;
            match stream {
                JobStream::Stdout => {
                    let mut writer = io::stdout().lock();
                    writer.write_all(&output.data)?;
                    writer.flush()?;
                }
                JobStream::Stderr => {
                    let mut writer = io::stderr().lock();
                    writer.write_all(&output.data)?;
                    writer.flush()?;
                }
            }
        }
        match status.state.state {
            JobStateKind::Exited | JobStateKind::Failed | JobStateKind::Interrupted
                if stdout_eof && stderr_eof =>
            {
                return match status.state.state {
                    JobStateKind::Exited => {
                        Ok(status.state.code.ok_or("exited job omitted its code")?)
                    }
                    JobStateKind::Failed | JobStateKind::Interrupted => Err(unknown(
                        "terminal status",
                        &io::Error::other(format!("job ended in {}", state_name(&status))),
                    )
                    .into()),
                    JobStateKind::Prepared | JobStateKind::Running => unreachable!(),
                };
            }
            JobStateKind::Prepared
            | JobStateKind::Running
            | JobStateKind::Exited
            | JobStateKind::Failed
            | JobStateKind::Interrupted => {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
        read_failures = 0;
    }
}

fn sftp_failure_may_be_existing_file(error: &SshClientError) -> bool {
    matches!(
        error,
        SshClientError::Sftp(russh_sftp::client::error::Error::Status(status))
            if status.status_code == russh_sftp::protocol::StatusCode::Failure
    )
}

enum PreparedJob {
    Start(Start),
    Status(Status),
    Output,
}

fn validate_job_id(id: &str) -> Result<(), io::Error> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "job ID must be a canonical lowercase UUID",
        )
    })?;
    if parsed.to_string() != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job ID must be a canonical lowercase UUID",
        ));
    }
    Ok(())
}

fn validate_job_spec(spec: &JobSpec) -> Result<(), io::Error> {
    let is_absolute = |value: &str| {
        Path::new(value).is_absolute()
            || (value.as_bytes().get(1) == Some(&b':')
                && value
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic))
            || value.starts_with("\\\\")
    };
    if !is_absolute(&spec.program)
        || spec.program.as_bytes().contains(&0)
        || spec.args.iter().any(|arg| arg.as_bytes().contains(&0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job program must be an absolute path and arguments must not contain NUL",
        ));
    }
    if let Some(cwd) = &spec.cwd
        && (!is_absolute(cwd) || cwd.as_bytes().contains(&0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job working directory must be an absolute path",
        ));
    }
    if spec.source_sha256.len() != 64
        || !spec
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job source SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn state_name(status: &JobStatus) -> &'static str {
    match status.state.state {
        JobStateKind::Prepared => "prepared",
        JobStateKind::Running => "running",
        JobStateKind::Exited => "exited",
        JobStateKind::Failed => "failed",
        JobStateKind::Interrupted => "interrupted",
    }
}

fn state_code(status: &JobStatus) -> String {
    status
        .state
        .code
        .map_or_else(|| "null".into(), |code| code.to_string())
}

fn write_job_status(status: &JobStatus) -> io::Result<()> {
    let value = job_status_value(status);
    serde_json::to_writer(io::stdout().lock(), &value)?;
    io::stdout().lock().write_all(b"\n")
}

fn job_status_value(status: &JobStatus) -> serde_json::Value {
    let state = match status.state.code {
        Some(code) => serde_json::json!({"state": state_name(status), "code": code}),
        None => serde_json::json!({"state": state_name(status)}),
    };
    serde_json::json!({"id": status.id, "state": state})
}

fn load_host_spec(path: &Path) -> io::Result<HostSpec> {
    let bytes = read_existing_file(path, MAX_CONFIG_BYTES)?;
    let mut config: HostSpec = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    if config.identity.is_relative() {
        config.identity = base.join(config.identity);
    }
    if let Some(gateway) = &mut config.gateway
        && gateway.identity.is_relative()
    {
        gateway.identity = base.join(&gateway.identity);
    }
    Ok(config)
}

fn read_existing_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source must be a bounded regular file, not a symlink",
        ));
    }
    read_limited(File::open(path)?, max_bytes)
}

fn read_limited(mut reader: impl Read, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn create_new_output(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        if let Err(cleanup) = fs::remove_file(path) {
            return Err(io::Error::other(format!(
                "SFTP local output write failed: {error}; owned partial file cleanup failed: {cleanup}",
            )));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_start_parses_exact_argument_vector_after_separator() {
        let cli = Cli::try_parse_from([
            "hostlink",
            "job",
            "start",
            "--config",
            "host.json",
            "--program",
            "/opt/tests/bin",
            "--source-sha256",
            &"a".repeat(64),
            "--",
            "--list",
            "suite::test name",
        ])
        .unwrap();
        let Command::Job {
            command:
                JobCommand::Start {
                    program,
                    source_sha256,
                    args,
                    ..
                },
        } = cli.command
        else {
            panic!("expected job start command");
        };
        assert_eq!(program, "/opt/tests/bin");
        assert_eq!(source_sha256, "a".repeat(64));
        assert_eq!(args, ["--list", "suite::test name"]);
    }

    #[test]
    fn migration_preflight_requires_all_local_explicit_inputs() {
        let cli = Cli::try_parse_from([
            "hostlink",
            "migration",
            "preflight",
            "--old-hub",
            "hub.json",
            "--old-controller",
            "controller.json",
            "--old-agent",
            "agent.json",
            "--new-agent",
            "new-agent.json",
            "--new-host",
            "host.json",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Migration { .. }));
    }

    #[test]
    fn run_parses_test_runner_arguments_without_shell_reinterpretation() {
        let cli = Cli::try_parse_from([
            "hostlink",
            "run",
            "--config",
            "host.json",
            "--binary",
            "runner",
            "--id",
            "00000000-0000-4000-8000-000000000000",
            "--",
            "--list",
            "suite::test name",
            "--exact",
        ])
        .unwrap();
        let Command::Run { args, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(args, ["--list", "suite::test name", "--exact"]);
    }

    #[test]
    fn run_local_binary_validation_rejects_directories_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        assert!(read_existing_file(root.path(), MAX_FILE_BYTES).is_err());
        let binary = root.path().join("runner");
        fs::write(&binary, b"test binary").unwrap();
        assert_eq!(
            read_existing_file(&binary, MAX_FILE_BYTES).unwrap(),
            b"test binary"
        );
        let oversized = root.path().join("oversized-runner");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        assert!(read_existing_file(&oversized, MAX_FILE_BYTES).is_err());
        #[cfg(unix)]
        {
            let link = root.path().join("runner-link");
            std::os::unix::fs::symlink(&binary, &link).unwrap();
            assert!(read_existing_file(&link, MAX_FILE_BYTES).is_err());
        }
    }

    #[test]
    fn run_staging_name_is_the_digest_bound_seal_name() {
        let bytes = b"runner payload";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let artifact_name = sealed_artifact_name(&digest).unwrap();
        assert_eq!(artifact_name.len(), 71);
        assert_eq!(artifact_name, format!("{digest}.upload"));
        let prepared = PreparedRun {
            id: "00000000-0000-4000-8000-000000000000".into(),
            bytes: bytes.to_vec(),
            digest: digest.clone(),
            artifact_name: artifact_name.clone(),
            args: vec!["--list".into()],
        };
        assert_eq!(
            prepared.artifact_name,
            format!("{}.upload", prepared.digest)
        );
        let seal = prepared.seal_request();
        assert_eq!(seal.name, prepared.artifact_name);
        assert_eq!(seal.sha256, prepared.digest);
        assert_eq!(seal.size, bytes.len() as u64);
        assert_eq!(prepared.bytes, bytes);
    }

    #[test]
    fn only_generic_remote_sftp_failure_can_enter_exact_seal_verification() {
        let failure = || {
            SshClientError::Sftp(russh_sftp::client::error::Error::Status(
                russh_sftp::protocol::Status {
                    id: 1,
                    status_code: russh_sftp::protocol::StatusCode::Failure,
                    error_message: "Failure".into(),
                    language_tag: "en-US".into(),
                },
            ))
        };
        let denied = SshClientError::Sftp(russh_sftp::client::error::Error::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: russh_sftp::protocol::StatusCode::PermissionDenied,
                error_message: "Permission denied".into(),
                language_tag: "en-US".into(),
            },
        ));
        assert!(sftp_failure_may_be_existing_file(&failure()));
        assert!(!sftp_failure_may_be_existing_file(&denied));
        assert!(!sftp_failure_may_be_existing_file(&SshClientError::Timeout));
    }

    #[test]
    fn job_subcommands_reject_invalid_required_values() {
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "job",
                "status",
                "--config",
                "host.json",
                "--id",
                "not-a-uuid",
            ])
            .is_ok()
        );
        assert!(validate_job_id("not-a-uuid").is_err());
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "job",
                "output",
                "--config",
                "host.json",
                "--id",
                "00000000-0000-4000-8000-000000000000",
                "--stream",
                "combined",
                "--offset",
                "0",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "job",
                "output",
                "--config",
                "host.json",
                "--id",
                "00000000-0000-4000-8000-000000000000",
                "--stream",
                "stdout",
            ])
            .is_err()
        );
    }

    #[test]
    fn job_start_validation_rejects_non_absolute_program_and_bad_digest() {
        let mut spec = JobSpec {
            program: "relative/program".into(),
            args: Vec::new(),
            cwd: None,
            source_sha256: "a".repeat(64),
        };
        assert!(validate_job_spec(&spec).is_err());
        spec.program = "/absolute/program".into();
        spec.source_sha256 = "A".repeat(64);
        assert!(validate_job_spec(&spec).is_err());
    }

    #[test]
    fn job_status_output_preserves_exit_code_and_omits_unknown_code() {
        let exited = JobStatus {
            id: "00000000-0000-4000-8000-000000000000".into(),
            state: hostlink::run::JobState {
                state: JobStateKind::Exited,
                code: Some(7),
            },
        };
        assert_eq!(job_status_value(&exited)["state"]["code"], 7);

        let running = JobStatus {
            id: exited.id,
            state: hostlink::run::JobState {
                state: JobStateKind::Running,
                code: None,
            },
        };
        assert!(job_status_value(&running)["state"].get("code").is_none());
    }

    #[test]
    fn host_config_rejects_unknown_fields_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("host.json");
        fs::write(&path, br#"{"endpoint":"127.0.0.1:27322","user":"hostlink","identity":"key","host_public_key":"pin","gateway":null,"unknown":true}"#).unwrap();
        assert!(load_host_spec(&path).is_err());
        #[cfg(unix)]
        {
            let symlink = root.path().join("link.json");
            std::os::unix::fs::symlink(path, &symlink).unwrap();
            assert!(load_host_spec(&symlink).is_err());
        }
    }

    #[test]
    fn new_output_never_overwrites_existing_data() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("out");
        create_new_output(&path, b"old").unwrap();
        assert!(create_new_output(&path, b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }
}
