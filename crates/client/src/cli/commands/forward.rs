use crate::cli::{
    args::Command,
    commands::{hosts::connect_target, hub::default_hub_config_path},
};
use hostlink::forward::{self, ForwardServer};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

pub(super) async fn dispatch(command: &Command) -> Result<Option<i32>, Box<dyn Error>> {
    match command {
        Command::Forward {
            config,
            host,
            listen,
            target,
        } => {
            forward_cli(config.as_deref(), host.as_deref(), *listen, *target).await?;
            Ok(Some(0))
        }
        Command::Rdp {
            config,
            host,
            listen_port,
        } => {
            let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *listen_port);
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3389);
            forward_cli(config.as_deref(), host.as_deref(), listen, target).await?;
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}

async fn forward_cli(
    config_path: Option<&Path>,
    host: Option<&str>,
    listen: SocketAddr,
    target: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    forward::validate_forward_listen(listen, false)?;
    if target.port() == 0 {
        return Err("forward target port must be nonzero".into());
    }
    let config_path = match config_path {
        Some(path) => path.to_owned(),
        None => default_hub_config_path()?,
    };
    let connection = connect_target(&config_path, host).await?;
    let server: ForwardServer = forward::start_local_forward(connection, listen, target).await?;
    eprintln!(
        "hostlink: forwarding {} to {} through pinned SSH; press Ctrl-C to stop",
        server.local_addr(),
        target
    );
    let signal = tokio::signal::ctrl_c().await;
    let shutdown = server.shutdown().await;
    match (signal, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(Box::new(error)),
        (Ok(()), Err(error)) => Err(Box::new(error)),
        (Err(signal), Err(cleanup)) => Err(format!(
            "Ctrl-C handling failed: {signal}; forward shutdown failed: {cleanup}"
        )
        .into()),
    }
}
