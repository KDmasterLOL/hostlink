use super::*;
use apalis_core::{
    backend::ext::BackendExt,
    error::WorkerError,
    task::{data::Data, task_id::TaskId},
    worker::{builder::WorkerBuilder, event::Event, ext::event_listener::EventListenerExt},
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
            let backend = runtime
                .store
                .worker_backend()
                .poll_with_interval(Duration::from_millis(100));
            // A fresh identity lets native heartbeat recovery see a crashed
            // predecessor instead of refreshing its stale worker row.
            let worker_name = format!("{}-{}", crate::jobs::WORKER_NAME, JobId::new());
            let worker = WorkerBuilder::new(worker_name)
                .backend(backend)
                .data(runtime.clone())
                .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_ACTIVE_JOBS))
                .on_event(move |_, event| {
                    if let Event::Error(error) = event {
                        eprintln!("hostlink-agent: durable job service error: {error}");
                    }
                })
                .build(consume);
            // Native Apalis Lock/Complete events own status and result
            // publication; no separate HostLink lifecycle or retry layer.
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
) -> io::Result<i32> {
    let runtime = Arc::clone(&runtime);
    if task.to_string() != snapshot.id.to_string() {
        return Err(io::Error::other("durable task identity mismatch"));
    }
    let id = snapshot.id;
    let active = runtime.shutdown.child_token();
    {
        let _start = runtime.start_lock.lock().await;
        let record = runtime
            .store
            .lookup(id, &snapshot.controller_key_sha256)
            .await?;
        if record.job != snapshot || !matches!(record.state, JobState::Prepared | JobState::Running)
        {
            return Err(io::Error::other(
                "task cancelled or immutable payload mismatch",
            ));
        }
        runtime
            .active_jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, active.clone());
    }
    let process_runtime = runtime.clone();
    // A separately owned task retains the runtime and process slot even when
    // the Apalis service future is dropped during backend shutdown.
    let process = tokio::spawn(async move {
        let result = consume_registered(process_runtime.clone(), snapshot, active).await;
        process_runtime
            .active_jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        result
    });
    process.await.map_err(io::Error::other)?
}

async fn consume_registered(
    runtime: Arc<JobRuntime>,
    snapshot: JobPayload,
    active: processkit::CancellationToken,
) -> io::Result<i32> {
    let mut backoff = Duration::from_millis(10);
    let (start, permit, record, update) = loop {
        let start = runtime.start_lock.lock().await;
        if !runtime.accepting.load(Ordering::Acquire) || active.is_cancelled() {
            return Err(io::Error::other("job cancelled or Agent is shutting down"));
        }
        let record = runtime
            .store
            .lookup(snapshot.id, &snapshot.controller_key_sha256)
            .await?;
        if record.job != snapshot || !matches!(record.state, JobState::Prepared | JobState::Running)
        {
            return Err(io::Error::other(
                "task cancelled or immutable payload mismatch",
            ));
        }
        let update = match database::try_update_lock(&runtime.store.root) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                drop(start);
                tokio::select! {
                    () = active.cancelled() => return Err(io::Error::other("job cancelled or Agent is shutting down")),
                    () = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error),
        };
        let permit = runtime
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(io::Error::other)?;
        break (start, permit, record, update);
    };
    drop(update);
    drop(start);
    let owner = record.controller_key_sha256.clone();
    let unconfirmed = Arc::new(AtomicBool::new(false));
    let result = run_job(runtime.clone(), owner, record, active, unconfirmed.clone()).await;
    if unconfirmed.load(Ordering::Acquire) {
        runtime
            .unknown_permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(permit);
        runtime.accepting.store(false, Ordering::Release);
        runtime.shutdown.cancel();
    } else {
        drop(permit);
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
#[path = "busy_tests.rs"]
mod busy_tests;
