use crate::cli::{args::HostTarget, commands::hosts::connect_target};
use hostlink::forward::{self, ForwardServer};
use std::{error::Error, net::SocketAddr};

pub(super) async fn forward_cli(
    host_target: &HostTarget,
    listen: SocketAddr,
    target: SocketAddr,
) -> Result<i32, Box<dyn Error>> {
    forward::validate_forward_listen(listen, false)?;
    if target.port() == 0 {
        return Err("forward target port must be nonzero".into());
    }
    let connection = connect_target(host_target).await?;
    let server: ForwardServer = forward::start_local_forward(connection, listen, target).await?;
    eprintln!(
        "hostlink: forwarding {} to {} through pinned SSH; press Ctrl-C to stop",
        server.local_addr(),
        target
    );
    let signal = tokio::signal::ctrl_c().await;
    let shutdown = server.shutdown().await;
    match (signal, shutdown) {
        (Ok(()), Ok(())) => Ok(0),
        (Err(error), Ok(())) => Err(Box::new(error)),
        (Ok(()), Err(error)) => Err(Box::new(error)),
        (Err(signal), Err(cleanup)) => Err(format!(
            "Ctrl-C handling failed: {signal}; forward shutdown failed: {cleanup}"
        )
        .into()),
    }
}
