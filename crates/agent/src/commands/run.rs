use crate::shared::load_config;
use clap::Args as ClapArgs;
use hostlink_agent::runtime;
use std::{io, path::PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[arg(long)]
    config: PathBuf,
}

pub(crate) async fn execute(args: Args) -> io::Result<()> {
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
    runtime::serve(&config, shutdown.cancelled_owned()).await?;
    Ok(())
}
