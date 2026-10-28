use crate::cli::args::{Command, JobCommand};
use hostlink::{
    connect::HostConnection,
    run::{Cancel, JobState, JobStatus, Output, Status},
};
use std::{
    error::Error,
    io::{self, Write},
};

pub(in crate::cli) use hostlink::run::validate_id as validate_job_id;

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

pub(super) fn validate(command: &Command) -> Result<(), Box<dyn Error>> {
    if let Command::Jobs {
        command:
            JobCommand::Status { id, .. } | JobCommand::Cancel { id, .. } | JobCommand::Logs { id, .. },
    } = command
    {
        validate_job_id(id)?;
    }
    Ok(())
}

pub(super) async fn execute(
    client: &mut HostConnection,
    command: &JobCommand,
) -> Result<i32, Box<dyn Error>> {
    match command {
        JobCommand::List { page, status, .. } => {
            let jobs = client.job_list(*page, status.as_deref()).await?;
            serde_json::to_writer(io::stdout().lock(), &jobs)?;
            println!();
            Ok(0)
        }
        JobCommand::Status { id, .. } => {
            let status = client.job_status(&Status { id: id.clone() }).await?;
            write_job_status(&status, io::stdout().lock())?;
            Ok(0)
        }
        JobCommand::Cancel { id, .. } => {
            let status=client.job_cancel(&Cancel { id: id.clone() }).await.map_err(|error| format!("job cancel outcome UNKNOWN for {}: {error}; query job status for this id before further action", id))?;
            write_job_status(&status, io::stdout().lock())?;
            Ok(0)
        }
        JobCommand::Logs {
            id, stream, offset, ..
        } => {
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
