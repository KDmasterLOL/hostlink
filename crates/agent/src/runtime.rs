//! Process-lifetime Agent supervision: SSH, Apalis jobs and reverse SSH tunnel.
//! This is not part of the embedded SSH protocol handler.

use crate::{AgentConfig, ssh};
use std::{future::Future, io};

/// Serves authenticated SSH/SFTP traffic on the configured loopback listener until shutdown.
pub async fn serve<F>(config: &AgentConfig, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    config.validate()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    serve_on(listener, config, shutdown).await
}

/// Serves on a listener that the caller has already bound.
///
/// Prebinding makes the endpoint ready before the serving task is scheduled, which is useful for
/// deterministic startup coordination and tests.
pub async fn serve_on<F>(
    listener: tokio::net::TcpListener,
    config: &AgentConfig,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    config.validate()?;
    let bound = listener.local_addr()?;
    if bound != config.listen || !bound.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "prebound SSH listener must match configured loopback address",
        ));
    }
    // The Agent owns this process-lifetime lock, not the Apalis job backend.
    // An updater must not replace its executable while it is running.
    let lifetime = crate::private_fs::open_lock(&config.jobs_root.join("runner.lock"))?;
    lifetime.try_lock().map_err(io::Error::other)?;
    let prepared = ssh::prepare(config)?;
    let cancellation = processkit::CancellationToken::new();
    let mut ssh = Box::pin(ssh::serve_prepared_until(
        listener,
        prepared,
        config.jobs_root.clone(),
        cancellation.clone().cancelled_owned(),
    ));
    let mut jobs = Box::pin(crate::jobs::serve_until(
        &config.jobs_root,
        config.board_listen,
        cancellation.clone(),
    ));
    let mut tunnel = Box::pin(async {
        if config.gateway.is_some() {
            crate::tunnel::run(config, cancellation.clone().cancelled_owned()).await
        } else {
            std::future::pending::<io::Result<()>>().await
        }
    });
    tokio::pin!(shutdown);
    let result = tokio::select! {
        result = &mut ssh => (0, result),
        result = &mut jobs => (1, result),
        result = &mut tunnel => (2, result),
        () = &mut shutdown => (3, Ok(())),
    };
    cancellation.cancel();
    let early = result.0 != 3;
    let mut outcome = result.1;
    if early && outcome.is_ok() {
        outcome = Err(io::Error::other("Agent service stopped before shutdown"));
    }
    let (ssh_result, jobs_result, tunnel_result) = tokio::join!(
        async { if result.0 != 0 { ssh.await } else { Ok(()) } },
        async { if result.0 != 1 { jobs.await } else { Ok(()) } },
        async {
            if result.0 != 2 && config.gateway.is_some() {
                tunnel.await
            } else {
                Ok(())
            }
        },
    );
    outcome = outcome.and(ssh_result).and(jobs_result).and(tunnel_result);
    lifetime.unlock()?;
    outcome
}
