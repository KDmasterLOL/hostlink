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
pub(in crate::ssh) struct JobWorker {
    pub(in crate::ssh) task: tokio::task::JoinHandle<io::Result<()>>,
    shutdown: processkit::CancellationToken,
}

impl Drop for JobWorker {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl JobWorker {
    pub(in crate::ssh) fn start(runtime: Arc<JobRuntime>) -> Self {
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
            let worker = WorkerBuilder::new(crate::durable::WORKER_NAME)
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
                    // Keep Apalis polling until process tasks have persisted
                    // their outcomes. Stopping earlier can park an in-flight
                    // SQLite Fetch transaction while services need that very
                    // connection to finish (CallAll drains before poll_close).
                    let _trees = stopping
                        .slots
                        .clone()
                        .acquire_many_owned(MAX_ACTIVE_JOBS as u32)
                        .await
                        .map_err(|e| WorkerError::BackendError(Box::new(e)))?;
                    Ok::<(), WorkerError>(())
                })
                .await
                .map_err(io::Error::other);
            runtime.accepting.store(false, Ordering::Release);
            runtime.shutdown.cancel();
            // Apalis returns immediately on a backend error and drops service
            // futures. Process tasks retain their own permits and runtime, so
            // even this path must drain tree teardown before releasing ownership.
            let _trees = runtime
                .slots
                .clone()
                .acquire_many_owned(MAX_ACTIVE_JOBS as u32)
                .await
                .map_err(io::Error::other)?;
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

async fn consume(
    snapshot: crate::durable::JobRecord,
    runtime: Data<Arc<JobRuntime>>,
    task: TaskId,
    worker: WorkerContext,
) -> io::Result<()> {
    let runtime = Arc::clone(&runtime);
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
    if matches!(
        current.state,
        JobState::Failed | JobState::Exited { .. } | JobState::Interrupted
    ) {
        return Ok(());
    }
    let permit = runtime
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(io::Error::other)?;
    let record = runtime
        .store
        .claim_dequeued(&snapshot, &task.to_string(), worker.name())
        .await?;
    let id = record.id;
    let owner = record.controller_key_sha256.clone();
    let active = Arc::new(JobCancellation {
        process: runtime.shutdown.child_token(),
        requested: AtomicBool::new(false),
    });
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
        let _permit = permit;
        let result = run_job(process_runtime.clone(), owner, record, active).await;
        process_runtime
            .active_jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        result
    });
    drop(start);
    process.await.map_err(io::Error::other)?
}
