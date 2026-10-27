use super::output::{CappedOutputWriter, open_job_output};
use super::*;

pub(in crate::ssh) async fn run_job(
    runtime: Arc<JobRuntime>,
    owner: String,
    record: crate::durable::JobRecord,
    active: Arc<JobCancellation>,
) -> io::Result<()> {
    let id = record.id;
    if verify_job_source(&record.spec).is_err() {
        return runtime
            .store
            .transition(id, &owner, JobState::Running, JobState::Failed)
            .await
            .map(|_| ());
    }
    let (out, out_sync) = match open_job_output(&runtime, id, JobOutput::Stdout) {
        Ok(files) => files,
        Err(_) => {
            return runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed)
                .await
                .map(|_| ());
        }
    };
    let (err, err_sync) = match open_job_output(&runtime, id, JobOutput::Stderr) {
        Ok(files) => files,
        Err(_) => {
            return runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed)
                .await
                .map(|_| ());
        }
    };
    let output_failed = Arc::new(AtomicBool::new(false));
    let cancel = active.process.clone();
    let mut command = processkit::Command::new(&record.spec.program)
        .args(&record.spec.args)
        .stdin(processkit::Stdin::empty())
        .stdout_raw_tee(CappedOutputWriter::new(
            out,
            output_failed.clone(),
            cancel.clone(),
        ))
        .stderr_raw_tee(CappedOutputWriter::new(
            err,
            output_failed.clone(),
            cancel.clone(),
        ))
        .output_buffer(processkit::OutputBufferPolicy::bounded(256).with_max_bytes(64 * 1024))
        .timeout(JOB_TIMEOUT)
        .timeout_grace(Duration::from_secs(2))
        .kill_on_parent_death()
        .cancel_on(cancel);
    if let Some(cwd) = &record.spec.cwd {
        command = command.current_dir(cwd);
    }
    // ProcessKit owns timeout, cancellation and child cleanup. Windows uses its Job Object,
    // including kill-on-close for the complete process tree; Linux uses its private process group.
    let outcome = match command.start().await {
        Ok(child) => child.drain().await,
        Err(error) => {
            // Only explicit launch failures prove that no child was started.
            // Unknown errors may include an unconfirmed teardown.
            let state = match error.reason() {
                processkit::ErrorReason::Spawn { .. }
                | processkit::ErrorReason::NotFound { .. } => JobState::Failed,
                _ => JobState::Interrupted,
            };
            return runtime
                .store
                .transition(id, &owner, JobState::Running, state)
                .await
                .map(|_| ());
        }
    };
    let sync_results =
        tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all())).await;
    let has_output_error = output_failed.load(Ordering::Acquire);
    let synced = matches!(sync_results, Ok((Ok(()), Ok(()))));
    let next = if runtime.shutdown.is_cancelled() || !synced {
        JobState::Interrupted
    } else {
        match outcome {
            // This error explicitly means the process tree could not be confirmed gone.
            Err(error) if matches!(error.reason(), processkit::ErrorReason::Teardown { .. }) => {
                JobState::Interrupted
            }
            Err(error) if matches!(error.reason(), processkit::ErrorReason::Cancelled { .. }) => {
                // ProcessKit only returns Cancelled after confirmed process-tree teardown.
                JobState::Failed
            }
            Err(_) => JobState::Interrupted,
            Ok(_) if has_output_error || active.requested.load(Ordering::Acquire) => {
                JobState::Failed
            }
            Ok(processkit::Outcome::Exited(code)) => JobState::Exited { code },
            Ok(
                processkit::Outcome::Signalled(_)
                | processkit::Outcome::TimedOut
                | processkit::Outcome::InactivityTimedOut,
            ) => JobState::Failed,
            // A future ProcessKit outcome must not become a fabricated terminal result.
            Ok(_) => JobState::Interrupted,
        }
    };
    runtime
        .store
        .transition(id, &owner, JobState::Running, next)
        .await
        .map(|_| ())
}
