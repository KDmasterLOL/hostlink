use super::*;
use apalis_core::{
    backend::ext::BackendExt,
    error::WorkerError,
    task::{data::Data, task_id::TaskId},
    worker::{
        builder::WorkerBuilder, context::WorkerContext, event::Event,
        ext::event_listener::EventListenerExt,
    },
};

/// One supervised queue consumer per Agent, never per SSH request. Dropping the
/// serving future signals cancellation; it cannot release the runner lease
/// while the consumer or any process-tree teardown still owns the runtime.
pub(crate) struct JobWorker {
    pub(crate) task: tokio::task::JoinHandle<io::Result<()>>,
    shutdown: processkit::CancellationToken,
}

impl Drop for JobWorker {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl JobWorker {
    pub(crate) fn start(runtime: Arc<JobRuntime>) -> Self {
        let shutdown = runtime.shutdown.clone();
        let task = tokio::spawn(async move {
            let stopping = runtime.clone();
            let errors = runtime.clone();
            let failed = Arc::new(AtomicBool::new(false));
            let failed_event = failed.clone();
            let backend = runtime
                .store
                .worker_backend()
                .poll_with_interval(Duration::from_millis(100));
            let worker = WorkerBuilder::new(crate::jobs::WORKER_NAME)
                .backend(backend)
                .data(runtime.clone())
                .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_ACTIVE_JOBS))
                .on_event(move |_, event| {
                    if matches!(event, Event::Error(_)) {
                        failed_event.store(true, Ordering::Release);
                        eprintln!("hostlink-agent: durable Apalis service failed; stopping admission and process trees");
                        errors.accepting.store(false, Ordering::Release);
                        errors.shutdown.cancel();
                    }
                })
                .build(consume);
            // No retry layer. Backend Lock/Complete events are disabled: only
            // atomic HostLink transactions may publish lifecycle and attempts.
            let result = worker
                .run_until(async move {
                    stopping.shutdown.cancelled().await;
                    {
                        let _start = stopping.start_lock.lock().await;
                        stopping.accepting.store(false, Ordering::Release);
                    }
                    drain(&stopping)
                        .await
                        .map_err(|e| WorkerError::BackendError(Box::new(e)))?;
                    Ok::<(), WorkerError>(())
                })
                .await
                .map_err(io::Error::other);
            runtime.accepting.store(false, Ordering::Release);
            runtime.shutdown.cancel();
            // Backend failure can drop the service future. Independent process
            // tasks still hold runtime/permits until teardown and publication.
            drain(&runtime).await?;
            if failed.load(Ordering::Acquire) {
                return Err(io::Error::other(
                    "durable Apalis service failed; persisted claims require reconciliation",
                ));
            }
            result
        });
        Self { task, shutdown }
    }
}

async fn drain(runtime: &JobRuntime) -> io::Result<()> {
    if !runtime
        .unknown_permits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty()
    {
        return Err(io::Error::other(
            "process teardown unconfirmed; preserve UNKNOWN",
        ));
    }
    let _trees = tokio::time::timeout(
        SHUTDOWN_GRACE,
        runtime
            .slots
            .clone()
            .acquire_many_owned(MAX_ACTIVE_JOBS as u32),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "unconfirmed process teardown or publication",
        )
    })?
    .map_err(io::Error::other)?;
    Ok(())
}

async fn consume(
    snapshot: crate::jobs::JobPayload,
    runtime: Data<Arc<JobRuntime>>,
    task: TaskId,
    worker: WorkerContext,
) -> io::Result<()> {
    let runtime = Arc::clone(&runtime);
    let mut backoff = Duration::from_millis(10);
    let (start, permit, record) = loop {
        let start = runtime.start_lock.lock().await;
        if !runtime.accepting.load(Ordering::Acquire) || runtime.shutdown.is_cancelled() {
            return Ok(());
        }
        // Cancellation may have durably completed a Prepared job after dequeue.
        // Re-read rather than launching the stale snapshot delivered by Apalis.
        let current = runtime
            .store
            .lookup(snapshot.id, &snapshot.controller_key_sha256)
            .await?;
        if current.started || current.state == JobState::Interrupted {
            return Err(io::Error::other(
                "started claim blocks replay; operation UNKNOWN",
            ));
        }
        if matches!(current.state, JobState::Failed | JobState::Exited { .. }) {
            return Ok(());
        }
        let permit = runtime
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(io::Error::other)?;
        match runtime
            .store
            .claim_dequeued(&snapshot, &task.to_string(), worker.name())
            .await
        {
            Ok(record) => break (start, permit, record),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // No claim was written. Keep this exact dequeue delivery alive,
                // but let STOP and Cancel acquire start_lock while the updater
                // inspects active_ids. Never block a Tokio thread on update.lock.
                drop(permit);
                drop(start);
                tokio::select! {
                    () = runtime.shutdown.cancelled() => return Ok(()),
                    () = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    };
    let id = record.id;
    let owner = record.controller_key_sha256.clone();
    let active = runtime.shutdown.child_token();
    runtime
        .active_jobs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id, active.clone());
    // This task is created ONLY by the fenced Apalis consumer, never by start.
    // It survives a dropped service future on backend failure. The supervisor
    // and Agent shutdown both await its permit through confirmed tree teardown.
    let process_runtime = runtime.clone();
    let process = tokio::spawn(async move {
        let result = run_job(process_runtime.clone(), owner, record, active).await;
        if result.is_err() {
            // Unknown process/persistence outcome: never free a capacity slot
            // or claim that the tree has been confirmed reaped. Shut down
            // admission and retain the runner lease until Agent termination.
            process_runtime
                .unknown_permits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(permit);
            process_runtime.accepting.store(false, Ordering::Release);
            process_runtime.shutdown.cancel();
        } else {
            process_runtime
                .active_jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            drop(permit);
        }
        result
    });
    drop(start);
    process.await.map_err(io::Error::other)?
}

#[cfg(all(test, target_os = "linux"))]
#[path = "busy_tests.rs"]
mod busy_tests;
