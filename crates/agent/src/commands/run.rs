use crate::shared::load_config;
use clap::Args as ClapArgs;
use hostlink_agent::runtime;
use std::{io, path::PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    config: PathBuf,
    /// Load and verify lifecycle configuration from the private root marker.
    #[arg(long, hide = true)]
    managed_service: bool,
    /// Internal owner-bound startup; one-use admission arrives through inherited stdin.
    #[arg(long, hide = true)]
    maintenance_start: bool,
}

pub(crate) async fn execute(args: Args) -> io::Result<()> {
    #[cfg(windows)]
    let managed_control = if args.managed_service || args.maintenance_start {
        Some(hostlink_agent::service::validate_managed_run(
            &args.config,
            args.maintenance_start,
        )?)
    } else {
        None
    };
    #[cfg(not(windows))]
    if args.managed_service || args.maintenance_start {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed lifecycle mode is available only on Windows",
        ));
    }
    let config = load_config(&args.config)?;
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_shutdown.cancel();
        }
    });
    // runtime::serve owns the reverse tunnel; another tunnel task would
    // compete for the same Agent identity and its allocated remote port.
    #[cfg(windows)]
    if let Some((pipe, token)) = managed_control {
        let control_shutdown = shutdown.clone();
        let control_finished = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        let mut server = Box::pin(runtime::serve(&config, server_shutdown.cancelled_owned()));
        let control = Box::pin(hostlink_agent::service::control_loop(
            pipe,
            token,
            control_shutdown,
            control_finished.clone(),
        ));
        tokio::select! {
            result = &mut server => {
                control_finished.cancel();
                result?;
            },
            result = control => {
                shutdown.cancel();
                control_finished.cancel();
                if let Err(error) = result {
                    let _ = server.await;
                    return Err(error);
                }
                server.await?;
            }
        }
    } else {
        runtime::serve(&config, shutdown.cancelled_owned()).await?;
    }
    #[cfg(not(windows))]
    runtime::serve(&config, shutdown.cancelled_owned()).await?;
    Ok(())
}
