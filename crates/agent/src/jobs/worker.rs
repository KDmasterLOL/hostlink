use super::*;
use apalis_core::{
    backend::ext::BackendExt, error::WorkerError, task::data::Data, worker::builder::WorkerBuilder,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub(super) struct ExecutionContext {
    pub(super) stop: processkit::CancellationToken,
    pub(super) uncertain: Arc<AtomicBool>,
}

pub(super) async fn execute(job: CommandJob, ctx: Data<ExecutionContext>) -> io::Result<i32> {
    if job.program.is_empty()
        || job.args.len() > 256
        || job.program.len() > 8192
        || job.args.iter().any(|arg| arg.len() > 8192)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid command bounds",
        ));
    }
    let timeout = Duration::from_secs(command_timeout_seconds(job.timeout_seconds)?);
    let group = processkit::ProcessGroup::new().map_err(io::Error::other)?;
    let trusted = match group.mechanism() {
        #[cfg(target_os = "linux")]
        processkit::Mechanism::CgroupV2 => true,
        #[cfg(windows)]
        processkit::Mechanism::JobObject => true,
        #[cfg(target_os = "freebsd")]
        processkit::Mechanism::ProcessReaper => true,
        _ => false,
    };
    if !trusted {
        return Err(io::Error::other("process containment unavailable"));
    }
    let mut command = processkit::Command::new(&job.program)
        .args(&job.args)
        .stdin(processkit::Stdin::empty())
        .output_buffer(processkit::OutputBufferPolicy::bounded(256).with_max_bytes(64 * 1024))
        .kill_on_parent_death();
    if let Some(cwd) = job.cwd {
        command = command.current_dir(cwd);
    }
    if ctx.stop.is_cancelled() {
        return Err(io::Error::other("Agent stopping"));
    }
    let child = group.start(&command).await.map_err(io::Error::other)?;
    let drain = child.drain();
    tokio::pin!(drain);
    let mut timed_out = false;
    let outcome = tokio::select! {
        outcome = &mut drain => outcome.map_err(io::Error::other),
        _ = ctx.stop.cancelled() => stop_and_drain(&group, &mut drain).await,
        _ = tokio::time::sleep(timeout) => {
            timed_out = true;
            stop_and_drain(&group, &mut drain).await
        }
    };
    let confirmed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let report = group
                .stop(Duration::ZERO, true)
                .await
                .map_err(io::Error::other)?;
            if report.members_after() == Some(0) {
                return Ok::<(), io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if !matches!(confirmed, Ok(Ok(()))) {
        ctx.uncertain.store(true, Ordering::Release);
        ctx.stop.cancel();
        return Err(io::Error::other("process group teardown not confirmed"));
    }
    if ctx.stop.is_cancelled() || timed_out {
        return Err(io::Error::other("Agent stopping or command timed out"));
    }
    match outcome? {
        processkit::Outcome::Exited(0) => Ok(0),
        processkit::Outcome::Exited(code) => {
            Err(io::Error::other(format!("command exited with code {code}")))
        }
        _ => Err(io::Error::other("process did not exit normally")),
    }
}

async fn stop_and_drain(
    group: &processkit::ProcessGroup,
    drain: impl std::future::Future<Output = processkit::Result<processkit::Outcome>>,
) -> io::Result<processkit::Outcome> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_, result) = tokio::try_join!(
            async { group.stop(Duration::ZERO, true).await.map(|_| ()) },
            drain
        )
        .map_err(io::Error::other)?;
        Ok(result)
    })
    .await
    .map_err(io::Error::other)?
}

/// Run exactly one worker and optionally the loopback-only board until shutdown.
///
/// # Errors
/// Fails on invalid addresses, private state, bind, worker or serving errors.
pub async fn serve_until(
    root: &Path,
    board_listen: Option<SocketAddr>,
    shutdown: processkit::CancellationToken,
) -> io::Result<()> {
    if board_listen.is_some_and(|a| !a.ip().is_loopback() || a.port() == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "board must use a nonzero loopback address",
        ));
    }
    let store = JobStore::open(root).await?;
    let listener = match board_listen {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    let backend = store
        .backend
        .clone()
        .poll_with_interval(Duration::from_millis(100));
    let uncertain = Arc::new(AtomicBool::new(false));
    let context = ExecutionContext {
        stop: shutdown.clone(),
        uncertain: uncertain.clone(),
    };
    let worker = WorkerBuilder::new(format!("hostlink-{}", ulid::Ulid::generate()))
        .backend(backend)
        .data(context)
        .layer(tower::limit::ConcurrencyLimitLayer::new(MAX_ACTIVE_JOBS))
        .build(execute);
    let stop = shutdown.clone();
    let worker_future = worker.run_until(async move {
        stop.cancelled().await;
        Ok::<(), WorkerError>(())
    });
    tokio::pin!(worker_future);
    let result = if let (Some(listener), Some(address)) = (listener, board_listen) {
        let stop = shutdown.clone();
        let router = super::board::router(&store, address);
        let server = async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { stop.cancelled().await })
                .await
        };
        tokio::pin!(server);
        tokio::select! {
            result = &mut worker_future => { shutdown.cancel(); result.map_err(io::Error::other) },
            result = &mut server => { shutdown.cancel(); let worker_result = worker_future.await.map_err(io::Error::other); result?; worker_result },
        }
    } else {
        worker_future.await.map_err(io::Error::other)
    };
    store.close().await;
    if uncertain.load(Ordering::Acquire) {
        return Err(io::Error::other("process teardown unconfirmed"));
    }
    result
}
