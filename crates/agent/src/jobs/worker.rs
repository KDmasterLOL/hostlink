use super::spool::{CappedOutputWriter, open_job_output};
use super::*;

pub(super) async fn run_job(
    runtime: Arc<JobRuntime>,
    owner: String,
    record: crate::jobs::JobView,
    active: processkit::CancellationToken,
) -> io::Result<()> {
    let id = record.id;
    // Once StartedClaims is committed a terminal Failed must have both
    // durable spool files. Prepare them before any source check can fail.
    let outputs = (|| {
        Ok::<_, io::Error>((
            open_job_output(&runtime, id, JobOutput::Stdout)?,
            open_job_output(&runtime, id, JobOutput::Stderr)?,
        ))
    })();
    let ((out, out_sync), (err, err_sync)) = match outputs {
        Ok(files) => files,
        Err(error) => {
            runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Interrupted)
                .await?;
            return Err(io::Error::other(format!(
                "cannot prepare durable output; UNKNOWN: {error}"
            )));
        }
    };
    let pump_ends = [
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ];
    let cancel = active.clone();
    let mut command = processkit::Command::new(&record.spec.program)
        .args(&record.spec.args)
        .stdin(processkit::Stdin::empty())
        .stdout_raw_tee(CappedOutputWriter::new(
            out,
            cancel.clone(),
            pump_ends[0].clone(),
        ))
        .stderr_raw_tee(CappedOutputWriter::new(
            err,
            cancel.clone(),
            pump_ends[1].clone(),
        ))
        .output_buffer(processkit::OutputBufferPolicy::bounded(256).with_max_bytes(64 * 1024))
        // The deadline is enforced against the shared ProcessGroup below.
        // ProcessKit's own timeout only kills the direct child in a shared
        // group. An inherited pipe can then keep its output pump alive until
        // the five-second abort, losing the raw tee's EOF flush.
        // Do not use cancel_on: ProcessKit 3.3.4 reports Cancelled before
        // checking pump read errors, even when the raw tee flushed successfully.
        .kill_on_parent_death();
    if let Some(cwd) = &record.spec.cwd {
        command = command.current_dir(cwd);
    }
    // Keep the group owner after the direct child exits: descendants may have
    // closed stdio and outlive drain(). Require an OS-backed empty-group report.
    let group = match processkit::ProcessGroup::new() {
        Ok(group) => group,
        Err(error) => {
            runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Interrupted)
                .await?;
            return Err(io::Error::other(format!(
                "cannot create process group; UNKNOWN: {error}"
            )));
        }
    };
    // Serialize the cancel check AND start with authenticated Cancel. A cancel
    // acknowledged before this gate must never execute; after start, the select
    // below stops the group while drain preserves ProcessKit's Io errors.
    let start = runtime.start_lock.lock().await;
    if active.is_cancelled() {
        drop(start);
        return fail_before_launch(&runtime, &owner, id, (out_sync, err_sync)).await;
    }
    // Re-authorize the controller's sealed source after queue delay, immediately
    // before ProcessKit starts. No launch-by-FD guarantee is implied.
    if verify_job_source(&runtime.store, &owner, &record.spec).is_err() {
        drop(start);
        return fail_before_launch(&runtime, &owner, id, (out_sync, err_sync)).await;
    }
    // POSIX process groups cannot contain setsid() descendants. Inspect the
    // actual created backend, never host_containment()'s prediction, BEFORE spawn.
    if !trusted_mechanism(group.mechanism()) {
        eprintln!(
            "hostlink-agent: job {id} rejected before launch: unsupported containment {:?}",
            group.mechanism()
        );
        drop(start);
        return fail_before_launch(&runtime, &owner, id, (out_sync, err_sync)).await;
    }
    let launched = group.start(&command).await;
    drop(start);
    let outcome = match launched {
        Ok(child) => {
            let drain = child.drain();
            tokio::pin!(drain);
            let outcome = tokio::select! {
                biased;
                outcome = &mut drain => outcome,
                () = active.cancelled() => {
                    // Kill the whole group before the pump's bounded EOF drain,
                    // including descendants that inherited stdout/stderr.
                    let (teardown, outcome) =
                        tokio::join!(group.stop(Duration::ZERO, true), &mut drain);
                    teardown.and(outcome)
                }
                () = tokio::time::sleep(JOB_TIMEOUT) => {
                    // A shared ProcessKit command timeout kills only the direct
                    // child. Own the deadline here so all descendants are
                    // terminated before drain can abort an output pump.
                    active.cancel();
                    let (teardown, outcome) =
                        tokio::join!(group.stop(Duration::ZERO, true), &mut drain);
                    teardown.and(outcome)
                }
            };
            if let Err(error) = confirm_group_drained(&group).await {
                runtime
                    .store
                    .transition(id, &owner, JobState::Running, JobState::Interrupted)
                    .await?;
                return Err(error);
            }
            outcome
        }
        Err(error) => {
            // Even a failed start must finish group teardown before publication.
            let teardown = confirm_group_drained(&group).await;
            // No output pumps exist for these proven launch failures.
            let synced =
                tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all()))
                    .await;
            let state = if teardown.is_ok()
                && matches!(synced, Ok((Ok(()), Ok(()))))
                && matches!(
                    error.reason(),
                    processkit::ErrorReason::Spawn { .. }
                        | processkit::ErrorReason::NotFound { .. }
                ) {
                JobState::Failed
            } else {
                JobState::Interrupted
            };
            runtime
                .store
                .transition(id, &owner, JobState::Running, state)
                .await?;
            return if state == JobState::Failed {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "ProcessKit could not confirm launch/teardown: {error}; group shutdown: {teardown:?}"
                )))
            };
        }
    };
    finish_job(
        &runtime,
        &owner,
        id,
        &active,
        outcome,
        &pump_ends,
        (out_sync, err_sync),
    )
    .await
}

pub(super) fn trusted_mechanism(mechanism: processkit::Mechanism) -> bool {
    match mechanism {
        #[cfg(target_os = "linux")]
        processkit::Mechanism::CgroupV2 => true,
        #[cfg(windows)]
        processkit::Mechanism::JobObject => true,
        #[cfg(target_os = "freebsd")]
        processkit::Mechanism::ProcessReaper => true,
        // Includes POSIX fallback, unsupported OSes and future enum variants.
        _ => false,
    }
}

// No OS start or output pump existed: synced empty spools prove definite failure.
async fn fail_before_launch(
    runtime: &JobRuntime,
    owner: &str,
    id: JobId,
    (out_sync, err_sync): (File, File),
) -> io::Result<()> {
    let synced =
        tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all())).await;
    let state = if matches!(synced, Ok((Ok(()), Ok(())))) {
        JobState::Failed
    } else {
        JobState::Interrupted
    };
    runtime
        .store
        .transition(id, owner, JobState::Running, state)
        .await?;
    if state == JobState::Failed {
        Ok(())
    } else {
        Err(io::Error::other(
            "pre-launch rejection could not synchronize empty output; UNKNOWN",
        ))
    }
}

// stop() returning Ok only confirms signal delivery. Its backend member count
// must reach zero AFTER the direct child was drained/reaped. Keep ownership while
// polling: neither an unknown count nor a successful kill is proof of completion.
async fn confirm_group_drained(group: &processkit::ProcessGroup) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let report = group
                .stop(Duration::ZERO, true)
                .await
                .map_err(io::Error::other)?;
            if report.members_after() == Some(0) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("process group not confirmed empty within 5s; UNKNOWN"))?
}

// A successful ProcessKit drain alone does not confirm raw tee completion:
// join_pumps can silently abort a straggler, and a read error also flushes.
// Require an error-free drain, both stream-end flushes AND fsync.
async fn finish_job(
    runtime: &JobRuntime,
    owner: &str,
    id: JobId,
    active: &processkit::CancellationToken,
    outcome: processkit::Result<processkit::Outcome>,
    pump_ends: &[Arc<AtomicBool>; 2],
    (out_sync, err_sync): (File, File),
) -> io::Result<()> {
    let drain_error = outcome
        .as_ref()
        .err()
        .map(|error| format!("{:?}", error.kind()));
    let unconfirmed_outcome = outcome.is_err();
    // Observe EOF before fsync, never afterwards: a late pump write must not
    // race a sync on the cloned FD and then manufacture durable completion.
    let pumps_ended = pump_ends.iter().all(|ended| ended.load(Ordering::Acquire));
    let sync_results =
        tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all())).await;
    let synced = matches!(sync_results, Ok((Ok(()), Ok(()))));
    let next = if runtime.shutdown.is_cancelled() || !synced || !pumps_ended {
        JobState::Interrupted
    } else {
        match outcome {
            Err(_) => JobState::Interrupted,
            // User cancellation and spool failure share the same monotonic token.
            // A racing natural exit must not hide either failure.
            Ok(_) if active.is_cancelled() => JobState::Failed,
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
        .transition(id, owner, JobState::Running, next)
        .await?;
    if unconfirmed_outcome || !synced || !pumps_ended {
        return Err(io::Error::other(format!(
            "ProcessKit did not confirm process-tree/output completion: drain_error={drain_error:?}, stdout_end={}, stderr_end={}, synced={synced}",
            pump_ends[0].load(Ordering::Acquire),
            pump_ends[1].load(Ordering::Acquire),
        )));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "worker_tests.rs"]
mod tests;
