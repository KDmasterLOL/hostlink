use crate::cli::{args::Command, commands::hub::configured_hub_client};
use futures::{StreamExt, stream};
use hostlink::{
    connect::{HostConnection, SshClientError},
    host::Host,
};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
    time::Duration,
};

#[derive(serde::Serialize)]
struct HostCheck {
    machine_id: String,
    name: String,
    status: &'static str,
    observed_at_unix: u64,
}

pub(super) async fn list_command(check: bool, json: bool) -> Result<i32, Box<dyn Error>> {
    let (client, config) = configured_hub_client()?;
    let hosts = client.list_hosts().await?;
    if !check {
        if json {
            serde_json::to_writer_pretty(io::stdout().lock(), &hosts)?;
            io::stdout().lock().write_all(b"\n")?;
        } else {
            for host in hosts {
                println!(
                    "{}\t{}\t{}\t{} {}\t{}\tgateway-loopback=127.0.0.1:{}",
                    host.name,
                    host.machine_id,
                    host.display_name.as_deref().unwrap_or(""),
                    host.os,
                    host.arch,
                    host.agent_version,
                    host.remote_port,
                );
            }
        }
        return Ok(0);
    }
    // Keep the inventory request fast and separate. Explicit --check reuses a
    // single authoritative set of Hub-approved routes, even when more than
    // one gateway is configured.
    let gateways = client.info().await.ok();
    let mut statuses: Vec<HostCheck> = stream::iter(hosts.into_iter().map(|host| {
        let config = &config;
        let gateways = gateways.as_ref();
        async move {
            let observed_at_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let status = match gateways {
                None => "unknown",
                Some(gateways) => {
                    match hostlink::hub::host_spec_from_approved_routes(
                        host.clone(),
                        gateways,
                        config,
                    )
                    .await
                    {
                        // Invalid operator route selection is not evidence that a
                        // remote host's public key changed.
                        Err(hostlink::hub::HubClientError::Invalid(_)) => "unknown",
                        Err(_) => "unknown",
                        Ok(spec) => {
                            match tokio::time::timeout(
                                Duration::from_secs(20),
                                HostConnection::connect(&spec),
                            )
                            .await
                            {
                                Ok(Ok(connection)) => match connection.close().await {
                                    Ok(()) => "online",
                                    Err(_) => "unknown",
                                },
                                Ok(Err(SshClientError::Russh(russh::Error::UnknownKey))) => {
                                    "identity_mismatch"
                                }
                                Ok(Err(_)) | Err(_) => "unreachable",
                            }
                        }
                    }
                }
            };
            HostCheck {
                machine_id: host.machine_id.to_string(),
                name: host.name,
                status,
                observed_at_unix,
            }
        }
    }))
    .buffer_unordered(4)
    .collect()
    .await;
    statuses.sort_by(|left, right| left.name.cmp(&right.name));
    if json {
        serde_json::to_writer_pretty(io::stdout().lock(), &statuses)?;
        io::stdout().lock().write_all(b"\n")?;
    } else {
        for status in statuses {
            println!(
                "{}\t{}\t{}\t{}",
                status.name, status.machine_id, status.status, status.observed_at_unix
            );
        }
    }
    Ok(0)
}

pub(super) async fn dispatch(command: &Command) -> Result<Option<i32>, Box<dyn Error>> {
    match command {
        Command::List { check, json } => Ok(Some(list_command(*check, *json).await?)),
        Command::Info { host } => {
            let (client, _) = configured_hub_client()?;
            let host = client.resolve_host(host).await?;
            serde_json::to_writer_pretty(io::stdout().lock(), &host)?;
            io::stdout().lock().write_all(b"\n")?;
            Ok(Some(0))
        }
        Command::Verify { host } => {
            let config_path = super::hub::default_hub_config_path()?;
            let connection = connect_target(&config_path, Some(host)).await?;
            connection.close().await?;
            println!("verified {} using pinned russh identity", host);
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}

pub(super) async fn connect_target(
    config_path: &Path,
    host: Option<&str>,
) -> Result<HostConnection, Box<dyn Error>> {
    match host {
        Some(host) => {
            let (client, config) = hostlink::hub::HubClient::from_file(config_path)?;
            let (_, connection) = Host::connect(&client, &config, host).await?;
            Ok(connection)
        }
        None => {
            let spec = crate::cli::load_host_spec(config_path)?;
            Ok(HostConnection::connect(&spec).await?)
        }
    }
}
