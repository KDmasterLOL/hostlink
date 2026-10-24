//! Append-only job state persistence and job-specific storage adaptation.

use super::*;

const JOB_CONTROL_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const JOB_CONTROL_LOCK_POLL: Duration = Duration::from_millis(10);

pub(super) fn acquire_job_control_lock(job_dir: &Path) -> io::Result<std::fs::File> {
    acquire_exclusive_file_lock(
        job_dir.join("control.lock"),
        JOB_CONTROL_LOCK_TIMEOUT,
        JOB_CONTROL_LOCK_POLL,
    )
}

pub(crate) fn job_dir(jobs_root: &Path, job_id: &str) -> io::Result<PathBuf> {
    if job_id.is_empty()
        || job_id.len() > 128
        || !job_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid job id",
        ));
    }
    let path = jobs_root.join(job_id);
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("job not found: {job_id}"),
        ));
    }
    Ok(path)
}

pub(super) fn write_next_state(job_dir: &Path, job: &AgentJobInfo) -> io::Result<()> {
    let sequence = latest_state_sequence(job_dir)?.map_or(0, |value| value + 1);
    write_state(job_dir, sequence, job)
}

pub(super) fn write_state(job_dir: &Path, sequence: u64, job: &AgentJobInfo) -> io::Result<()> {
    let previous = match latest_state_sequence(job_dir)? {
        Some(_) => Some(read_latest_state_file(job_dir)?),
        None => None,
    };
    let worker_starting = job.state == AgentJobState::Running
        && previous
            .as_ref()
            .is_some_and(|state| state.job.state == AgentJobState::Queued);
    let identities = JobProcessIdentities {
        version: 1,
        worker: identity_for_pid(
            job.worker_pid,
            previous.as_ref().and_then(|state| state.job.worker_pid),
            previous
                .as_ref()
                .and_then(|state| state.process_identities.worker.clone()),
            worker_starting,
        ),
        spawn_owner: identity_for_pid(
            job.spawn_owner_pid,
            previous
                .as_ref()
                .and_then(|state| state.job.spawn_owner_pid),
            previous
                .as_ref()
                .and_then(|state| state.process_identities.spawn_owner.clone()),
            false,
        ),
        process: identity_for_pid(
            job.process_pid,
            previous.as_ref().and_then(|state| state.job.process_pid),
            previous
                .as_ref()
                .and_then(|state| state.process_identities.process.clone()),
            false,
        ),
    };
    write_state_with_identities(job_dir, sequence, job, identities)
}

fn identity_for_pid(
    pid: Option<u32>,
    previous_pid: Option<u32>,
    previous: Option<ProcessIdentity>,
    recapture_missing_identity: bool,
) -> Option<ProcessIdentity> {
    let pid = pid?;
    if previous_pid == Some(pid) {
        if let Some(previous) = previous.filter(|identity| identity.pid == pid) {
            return Some(previous);
        }
        if !recapture_missing_identity {
            return None;
        }
    }
    ProcessIdentity::capture(pid)
}

pub(super) fn write_state_with_identities(
    job_dir: &Path,
    sequence: u64,
    job: &AgentJobInfo,
    process_identities: JobProcessIdentities,
) -> io::Result<()> {
    let final_path = job_dir.join(format!("state-{sequence:06}.json"));
    let temp = job_dir.join(format!(".state-{sequence:06}-{}.tmp", std::process::id()));
    write_new_json_file(
        &temp,
        &JobStateFile {
            version: JOB_SCHEMA_VERSION,
            job: job.clone(),
            process_identities,
        },
    )?;
    onec_core::move_file_atomically(&temp, &final_path)?;
    Ok(())
}

pub(super) fn read_latest_state(job_dir: &Path) -> io::Result<AgentJobInfo> {
    Ok(read_latest_state_file(job_dir)?.job)
}

pub(super) fn read_latest_state_file(job_dir: &Path) -> io::Result<JobStateFile> {
    let sequence = latest_state_sequence(job_dir)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "job state is missing"))?;
    let state: JobStateFile = read_json_file_bounded(
        &job_dir.join(format!("state-{sequence:06}.json")),
        JOB_STATE_MAX_BYTES,
    )?;
    if state.version != JOB_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported job state version",
        ));
    }
    Ok(state)
}

pub(super) fn latest_state_sequence(job_dir: &Path) -> io::Result<Option<u64>> {
    let mut latest = None;
    for entry in fs::read_dir(job_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(number) = name
            .strip_prefix("state-")
            .and_then(|v| v.strip_suffix(".json"))
            && let Ok(number) = number.parse::<u64>()
        {
            latest = Some(latest.map_or(number, |value: u64| value.max(number)));
        }
    }
    Ok(latest)
}

pub(super) fn apply_log_truncation_flags(job_dir: &Path, job: &mut AgentJobInfo) -> io::Result<()> {
    job.stdout_log_truncated |=
        RetainedLog::new(job_dir.join("stdout.log"))?.storage_truncated()?;
    job.stderr_log_truncated |=
        RetainedLog::new(job_dir.join("stderr.log"))?.storage_truncated()?;
    Ok(())
}
