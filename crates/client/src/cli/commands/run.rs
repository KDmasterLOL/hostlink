use crate::cli::{
    MAX_FILE_BYTES,
    args::{Command, JobCommand},
    commands::job::{self, state_name},
    read_existing_file,
};
use hostlink::{
    HostSpec,
    connect::{HostConnection, SshClientError},
    run::{JobState, JobStream, Output, Status},
};
use std::{
    error::Error,
    io::{self, Write},
};

pub(in crate::cli) struct PreparedRun {
    pub(in crate::cli) id: String,
    pub(in crate::cli) bytes: Vec<u8>,
    pub(in crate::cli) wait: bool,
    pub(in crate::cli) args: Vec<String>,
}

pub(super) async fn execute(
    client: &mut HostConnection,
    request: PreparedRun,
    host: &HostSpec,
    target_hint: &str,
) -> Result<i32, Box<dyn Error>> {
    let unknown = |stage: &str, error: &dyn Error| {
        format!(
            "run outcome UNKNOWN during {stage} for {}: {error}; do not rerun or resend start; inspect with `hostlink jobs status {} --id {}` and `hostlink jobs logs {} --id {} --stream stdout --offset 0` (repeat for stderr and returned offsets)",
            request.id, target_hint, request.id, target_hint, request.id,
        )
    };

    let status = client
        .job_run(&request.id, &request.bytes, &request.args)
        .await
        .map_err(|error| unknown("upload/seal/start", &error))?;
    if !request.wait {
        job::write_job_status(&status, io::stdout().lock())?;
        return Ok(0);
    }

    wait_for_job(client, &request.id, host, target_hint).await
}

async fn wait_for_job(
    client: &mut HostConnection,
    id: &str,
    host: &HostSpec,
    target_hint: &str,
) -> Result<i32, Box<dyn Error>> {
    let unknown = |stage: &str, error: &dyn Error| {
        format!(
            "run outcome UNKNOWN during {stage} for {id}: {error}; do not rerun or resend start; inspect with `hostlink jobs status {target_hint} --id {id}` and `hostlink jobs logs {target_hint} --id {id} --stream stdout --offset 0` (repeat for stderr and returned offsets)"
        )
    };
    let (mut stdout_offset, mut stderr_offset) = (0_u64, 0_u64);
    let (mut stdout_eof, mut stderr_eof) = (false, false);
    // Total transport failures for this wait, including alternating stream failures.
    let mut read_failures = 0_u8;
    loop {
        let status = match client.job_status(&Status { id: id.into() }).await {
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
                    id: id.into(),
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
            JobState::Interrupted => return Err(unknown("job UNKNOWN", &io::Error::other("Agent cannot prove completion; inspect status and partial logs before reconciliation")).into()),
            JobState::Failed if stdout_eof && stderr_eof => {
                return Err(unknown(
                    "terminal status",
                    &io::Error::other(format!("job ended in {}", state_name(&status))),
                )
                .into());
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(150)).await,
        }
    }
}

pub(super) fn prepare(command: &Command) -> Result<Option<PreparedRun>, Box<dyn Error>> {
    let Command::Jobs {
        command:
            JobCommand::Run {
                binary,
                id,
                args,
                wait,
                ..
            },
    } = command
    else {
        return Ok(None);
    };
    let bytes = read_existing_file(binary, MAX_FILE_BYTES)?;
    let id = id
        .clone()
        .unwrap_or_else(|| ulid::Ulid::generate().to_string());
    job::validate_job_id(&id)?;
    if args.iter().any(|arg| arg.as_bytes().contains(&0)) {
        return Err("run arguments must not contain NUL".into());
    }
    if serde_json::to_vec(args)?.len() > 60 * 1024 {
        return Err("run arguments exceed 60 KiB".into());
    }
    eprintln!("hostlink: job id: {id}");
    Ok(Some(PreparedRun {
        id,
        bytes,
        wait: *wait,
        args: args.clone(),
    }))
}

#[cfg(all(test, unix))]
#[path = "../tests/wait.rs"]
mod wait_tests;
