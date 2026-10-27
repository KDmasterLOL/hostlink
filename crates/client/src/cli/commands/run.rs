use crate::cli::{
    MAX_FILE_BYTES,
    args::Command,
    commands::job::{self, state_name},
    read_existing_file,
};
use hostlink::{
    HostSpec,
    connect::{HostConnection, SshClientError},
    run::{JobSpec, JobState, JobStream, Output, Seal, Start, Status, sealed_artifact_name},
};
use sha2::{Digest as _, Sha256};
use std::{
    error::Error,
    io::{self, Write},
};

pub(in crate::cli) struct PreparedRun {
    pub(in crate::cli) id: String,
    pub(in crate::cli) bytes: Vec<u8>,
    pub(in crate::cli) digest: String,
    pub(in crate::cli) artifact_name: String,
    pub(in crate::cli) args: Vec<String>,
}

impl PreparedRun {
    pub(in crate::cli) fn seal_request(&self) -> Seal {
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
    target_hint: &str,
) -> Result<i32, Box<dyn Error>> {
    let unknown = |stage: &str, error: &dyn Error| {
        format!(
            "run outcome UNKNOWN during {stage} for {}: {error}; do not rerun or resend start; inspect with `hostlink job status {} --id {}` and `hostlink job output {} --id {} --stream stdout --offset 0` (repeat for stderr and returned offsets)",
            request.id, target_hint, request.id, target_hint, request.id,
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
        match status.state {
            JobState::Exited { code } if stdout_eof && stderr_eof => return Ok(code),
            JobState::Failed | JobState::Interrupted if stdout_eof && stderr_eof => {
                return Err(unknown(
                    "terminal status",
                    &io::Error::other(format!("job ended in {}", state_name(&status))),
                )
                .into());
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(150)).await,
        }
        read_failures = 0;
    }
}

pub(in crate::cli) fn sftp_failure_may_be_existing_file(error: &SshClientError) -> bool {
    matches!(
        error,
        SshClientError::Sftp(russh_sftp::client::error::Error::Status(status))
            if status.status_code == russh_sftp::protocol::StatusCode::Failure
    )
}

pub(super) fn prepare(command: &Command) -> Result<Option<PreparedRun>, Box<dyn Error>> {
    let Command::Run {
        binary, id, args, ..
    } = command
    else {
        return Ok(None);
    };
    let bytes = read_existing_file(binary, MAX_FILE_BYTES)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let artifact_name = sealed_artifact_name(&digest)?;
    let id = id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    job::validate_job_id(&id)?;
    if args.iter().any(|arg| arg.as_bytes().contains(&0)) {
        return Err("run arguments must not contain NUL".into());
    }
    if serde_json::to_vec(args)?.len() > 64 * 1024 {
        return Err("run arguments exceed 64 KiB".into());
    }
    eprintln!("hostlink: job id: {id}");
    Ok(Some(PreparedRun {
        id,
        bytes,
        digest,
        artifact_name,
        args: args.clone(),
    }))
}

pub(super) async fn execute(
    client: &mut HostConnection,
    request: PreparedRun,
    spec: &HostSpec,
    target_hint: &str,
) -> Result<i32, Box<dyn Error>> {
    run_test_binary(client, request, spec, target_hint).await
}
