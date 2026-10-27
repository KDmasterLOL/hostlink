use crate::cli::args::{Command, JobCommand};
use hostlink::{
    connect::HostConnection,
    run::{Cancel, JobSpec, JobState, JobStatus, Output, Start, Status},
};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

pub(in crate::cli) enum PreparedJob {
    Start(Start),
    Status(Status),
    Cancel(Cancel),
    Output,
}

pub(in crate::cli) fn validate_job_id(id: &str) -> Result<(), io::Error> {
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

pub(in crate::cli) fn validate_job_spec(spec: &JobSpec) -> Result<(), io::Error> {
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

pub(in crate::cli) fn state_name(status: &JobStatus) -> &'static str {
    match status.state {
        JobState::Prepared => "prepared",
        JobState::Running => "running",
        JobState::Exited { .. } => "exited",
        JobState::Failed => "failed",
        JobState::Interrupted => "interrupted",
    }
}

pub(in crate::cli) fn state_code(status: &JobStatus) -> String {
    match status.state {
        JobState::Exited { code } => code.to_string(),
        _ => "null".into(),
    }
}

pub(in crate::cli) fn write_job_status(
    status: &JobStatus,
    mut writer: impl Write,
) -> io::Result<()> {
    serde_json::to_writer(&mut writer, status)?;
    writer.write_all(b"\n")
}

pub(super) fn prepare(command: &Command) -> Result<Option<PreparedJob>, Box<dyn Error>> {
    match command {
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
            let encoded = serde_json::to_vec(
                &serde_json::json!({"version":1,"op":"start","id":request.id,"spec":request.spec}),
            )?;
            if encoded.len() > 64 * 1024 {
                return Err("job request exceeds 64 KiB".into());
            }
            eprintln!("hostlink: job id: {}", request.id);
            Ok(Some(PreparedJob::Start(request)))
        }
        Command::Job {
            command: JobCommand::Status { id, .. },
        } => {
            validate_job_id(id)?;
            Ok(Some(PreparedJob::Status(Status { id: id.clone() })))
        }
        Command::Job {
            command: JobCommand::Cancel { id, .. },
        } => {
            validate_job_id(id)?;
            Ok(Some(PreparedJob::Cancel(Cancel { id: id.clone() })))
        }
        Command::Job {
            command: JobCommand::Output { id, .. },
        } => {
            validate_job_id(id)?;
            Ok(Some(PreparedJob::Output))
        }
        _ => Ok(None),
    }
}

pub(super) async fn execute(
    client: &mut HostConnection,
    command: &JobCommand,
    prepared: PreparedJob,
    target_hint: &str,
) -> Result<i32, Box<dyn Error>> {
    match (command, prepared) {
        (JobCommand::Start { .. }, PreparedJob::Start(request)) => {
            let status = client.job_start(&request).await.map_err(|error| format!("job start outcome UNKNOWN for {}: {error}; query with `hostlink job status {} --id {}` before any further action", request.id, target_hint, request.id))?;
            write_job_status(&status, io::stdout().lock())?;
            Ok(0)
        }
        (JobCommand::Status { .. }, PreparedJob::Status(request)) => {
            let status = client.job_status(&request).await?;
            write_job_status(&status, io::stdout().lock())?;
            Ok(0)
        }
        (JobCommand::Cancel { .. }, PreparedJob::Cancel(request)) => {
            let status=client.job_cancel(&request).await.map_err(|error| format!("job cancel outcome UNKNOWN for {}: {error}; query job status for this id before further action", request.id))?;
            write_job_status(&status, io::stdout().lock())?;
            Ok(0)
        }
        (
            JobCommand::Output {
                id, stream, offset, ..
            },
            PreparedJob::Output,
        ) => {
            let output = client
                .job_output(&Output {
                    id: id.clone(),
                    stream: *stream,
                    offset: *offset,
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
    }
}
