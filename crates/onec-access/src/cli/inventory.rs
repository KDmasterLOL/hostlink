use super::*;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

// Bound connection pressure on the hub's SSH gateways while probing the
// enrolled fleet. Each host remains independent and output stays name-sorted.
const MAX_HELLO_PROBES: usize = 2;
const MAX_HUB_ROUTE_RESOLUTIONS: usize = 8;
const INVENTORY_ROUTE_FAILURE: &str =
    "managed route could not be resolved; agent state is unknown.";
const HELLO_POINT_IN_TIME_NOTE: &str =
    "Authenticated Hello responded at this time; later SSH or exec availability is not guaranteed.";

#[derive(Debug, thiserror::Error)]
#[error("authenticated Hello identity does not match the selected managed host")]
struct HelloIdentityMismatch;

async fn probe_in_order<T, F>(
    probes: impl IntoIterator<Item = F>,
    max_concurrency: usize,
) -> AppResult<Vec<T>>
where
    T: Send + 'static,
    F: Future<Output = AppResult<T>> + Send + 'static,
{
    if max_concurrency == 0 {
        return Err(crate::invalid_config(
            "inventory probe concurrency must be positive".to_owned(),
        ));
    }
    let mut pending = tokio::task::JoinSet::new();
    let mut completed = BTreeMap::new();

    for (index, probe) in probes.into_iter().enumerate() {
        if pending.len() >= max_concurrency {
            let result = pending.join_next().await.ok_or_else(|| {
                crate::invalid_config("inventory probe worker disappeared".to_owned())
            })?;
            let (index, row): (usize, AppResult<T>) = result.map_err(|error| {
                crate::invalid_config(format!("inventory probe worker failed: {error}"))
            })?;
            completed.insert(index, row?);
        }
        pending.spawn(async move { (index, probe.await) });
    }
    while let Some(result) = pending.join_next().await {
        let (index, row): (usize, AppResult<T>) = result.map_err(|error| {
            crate::invalid_config(format!("inventory probe worker failed: {error}"))
        })?;
        completed.insert(index, row?);
    }
    Ok(completed.into_values().collect())
}

#[derive(Debug)]
struct DiscoveredServer {
    name: String,
    server: Option<RemoteServer>,
    source: String,
    display_name: Option<String>,
}

pub(super) fn failure_status(_carrier: RemoteCarrier) -> &'static str {
    // A failed Hello proves only that the authenticated transport did not complete. Neither
    // carrier tells us whether the resident agent is stopped or temporarily unreachable.
    "unknown"
}

fn observed_at_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn transport_failure_phase(error: &str) -> &'static str {
    fn first_match(error: &str, markers: &[(&str, &'static str)]) -> Option<&'static str> {
        markers
            .iter()
            .filter_map(|(needle, phase)| error.find(needle).map(|at| (at, *phase)))
            .min_by_key(|(at, _)| *at)
            .map(|(_, phase)| phase)
    }

    const STABLE_MARKERS: &[(&str, &str)] = &[
        ("gateway_direct_tcpip", "gateway_direct_tcpip"),
        ("gateway_connect", "gateway_connect"),
        ("target_ssh_handshake", "target_ssh_handshake"),
        ("target_ssh_auth", "target_ssh_auth"),
        ("agent_control", "agent_control"),
        ("target_direct_tcpip", "target_direct_tcpip"),
    ];
    const LEGACY_MARKERS: &[(&str, &str)] = &[
        ("opening gateway direct-tcpip", "gateway_direct_tcpip"),
        ("target SSH host", "target_ssh_handshake"),
    ];

    first_match(error, STABLE_MARKERS)
        .or_else(|| first_match(error, LEGACY_MARKERS))
        .or_else(|| {
            error
                .contains("all approved gateway routes failed")
                .then_some("gateway_connect")
        })
        .unwrap_or("transport_establishment")
}

fn hello_identity_status(expected_name: &str, actual_name: &str) -> (&'static str, &'static str) {
    if actual_name.eq_ignore_ascii_case(expected_name) {
        ("online", "authenticated_hello")
    } else {
        ("identity_mismatch", "authenticated_hello_identity_mismatch")
    }
}

fn require_hello_identity_match(expected_name: &str, actual_name: &str) -> AppResult<()> {
    if hello_identity_status(expected_name, actual_name).0 == "online" {
        Ok(())
    } else {
        Err(HelloIdentityMismatch.into())
    }
}

fn inventory_status_fields(
    hello: &AppResult<AgentResponseKind>,
    carrier: RemoteCarrier,
    expected_name: &str,
    observed_at: Option<u64>,
) -> serde_json::Value {
    match hello {
        Ok(AgentResponseKind::Hello { name, .. }) => {
            let (status, observation) = hello_identity_status(expected_name, name);
            let identity_match = status == "online";
            json!({
                "status": status,
                "status_observation": observation,
                "observed_at_unix_ms": observed_at,
                "status_scope": "point_in_time",
                "status_note": if identity_match {
                    HELLO_POINT_IN_TIME_NOTE
                } else {
                    "Authenticated Hello responded, but the agent name does not match the selected managed host."
                },
                "identity_match": identity_match,
            })
        }
        Ok(_) => json!({
            "status": "unknown",
            "status_observation": "unexpected_hello_response",
            "observed_at_unix_ms": observed_at,
            "status_scope": "point_in_time",
            "error": "Unexpected response during authenticated Hello; agent state is unknown.",
        }),
        Err(error) => {
            let phase_failure = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<hostlink_access::SshPhaseFailure>());
            let phase = phase_failure
                .map(hostlink_access::SshPhaseFailure::phase)
                .unwrap_or_else(|| transport_failure_phase(&error.to_string()));
            let diagnostic = format!(
                "{phase}: Hello transport failed; agent state is unknown. Check this route phase and retry."
            );
            let mut observation = json!({
                "status": failure_status(carrier),
                "status_observation": "hello_transport_failed",
                "observed_at_unix_ms": observed_at,
                "status_scope": "transport_attempt",
                "failure_phase": phase,
                "error": diagnostic,
            });
            if let Some(failure) = phase_failure {
                for (key, value) in failure.safe_diagnostic_fields() {
                    observation[key] = value;
                }
            }
            observation
        }
    }
}

fn route_resolution_failure_row(
    name: &str,
    source: &str,
    display_name: Option<&str>,
) -> serde_json::Value {
    let mut row = json!({
        "name": name,
        "source": source,
        "status": "unknown",
        "status_observation": "route_resolution_failed",
        "status_scope": "control_plane_attempt",
        "error": INVENTORY_ROUTE_FAILURE,
    });
    if let Some(label) = display_name {
        row["display_name"] = json!(label);
    }
    row
}

pub(super) fn recovery_hint(server: &RemoteServer) -> Option<&'static str> {
    if server.carrier == RemoteCarrier::GatewayControl
        && server.persistence_mode.as_deref() == Some("user-session")
    {
        Some(
            "user-session persistence is logon-scoped; restore the owning Windows user session or recover out-of-band, then verify the agent",
        )
    } else {
        None
    }
}

fn gateway_inventory(server: &RemoteServer) -> (Vec<serde_json::Value>, Option<String>) {
    let routes = server
        .gateways
        .iter()
        .map(|route| {
            json!({
                "host": route.host,
                "user": route.user,
                "port": route.port,
            })
        })
        .collect::<Vec<_>>();
    let primary = server
        .gateways
        .first()
        .map(|route| format!("{}@{}:{}", route.user, route.host, route.port));
    (routes, primary)
}

async fn discover_servers() -> AppResult<Vec<DiscoveredServer>> {
    let config_path = hub_config_path()?;
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink controller config {}; configure access before using managed hosts",
            config_path.display()
        ))
    })?;
    let ssh = sync_hub_ssh_hosts(&hub, false).await?;
    let mut agents = hub.list_agents().await?;
    agents.sort_by(|left, right| left.name.cmp(&right.name));
    let configured_hosts = ssh
        .configured_hosts
        .into_iter()
        .map(|host| host.to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>();
    probe_in_order(
        agents.into_iter().map(|agent| {
            let hub = hub.clone();
            let configured_hosts = configured_hosts.clone();
            async move {
                let ssh_ready = configured_hosts.contains(&agent.name.to_ascii_lowercase());
                let (server, source) = match hub_runtime_server(&hub, &agent, ssh_ready).await {
                    Ok((server, source)) => (Some(server), source),
                    Err(_) => (
                        None,
                        if ssh_ready {
                            "hub-target-ssh"
                        } else {
                            "hub-gateway-control"
                        },
                    ),
                };
                Ok(DiscoveredServer {
                    name: agent.name,
                    server,
                    source: source.to_owned(),
                    display_name: agent.display_name,
                })
            }
        }),
        MAX_HUB_ROUTE_RESOLUTIONS,
    )
    .await
}

pub(super) async fn list(json_output: bool) -> AppResult<()> {
    let servers = discover_servers().await?;
    let rows = probe_in_order(servers.into_iter().map(list_server_row), MAX_HELLO_PROBES).await?;
    if json_output {
        crate::cli::output::print_pretty_json(&rows);
    } else if rows.is_empty() {
        println!("No managed hosts are enrolled");
    } else {
        for row in rows {
            let status = row["status"].as_str().unwrap_or("unknown");
            let name = row["name"].as_str().unwrap_or("?");
            let hostname = row["hostname"].as_str().unwrap_or("-");
            let source = row["source"].as_str().unwrap_or("hub");
            let persistence = row["persistence_mode"].as_str().unwrap_or("unknown");
            let primary = row["gateway_primary"].as_str().unwrap_or("-");
            let display = row["display_name"]
                .as_str()
                .map(|label| format!("{name} ({label})"))
                .unwrap_or_else(|| name.to_owned());
            println!("{display}\t{status}\t{source}\t{hostname}\t{persistence}\t{primary}");
            if let Some(hint) = row["recovery_hint"].as_str() {
                println!("  recovery: {hint}");
            }
            if let Some(error) = row["error"].as_str() {
                println!("  diagnostic: {error}");
            } else if let Some(note) = row["status_note"].as_str() {
                println!("  observation: {note}");
            }
        }
    }
    Ok(())
}

async fn list_server_row(discovered: DiscoveredServer) -> AppResult<serde_json::Value> {
    let name = discovered.name;
    let source = discovered.source;
    let display_name = discovered.display_name;
    let Some(server) = discovered.server else {
        return Ok(route_resolution_failure_row(
            &name,
            &source,
            display_name.as_deref(),
        ));
    };
    let client = RemoteAgentClient::new(server.clone())?;
    let (gateway_routes, gateway_primary) = gateway_inventory(&server);
    let hello = client.hello().await;
    let observed_at = observed_at_unix_ms();
    let status_fields = inventory_status_fields(&hello, server.carrier, &server.name, observed_at);
    let mut row = match hello {
        Ok(AgentResponseKind::Hello {
            name,
            agent_version,
            hostname,
            os,
            capabilities,
            agent_executable,
            onec_executable,
        }) => json!({
            "name": server.name,
            "source": source,
            "persistence_mode_source": "hub_enrollment",
            "persistence_mode": server.persistence_mode,
            "agent_name": name,
            "agent_version": agent_version,
            "hostname": hostname,
            "os": os,
            "agent_capabilities": capabilities,
            "agent_executable": agent_executable,
            "onec_executable": onec_executable.as_deref(),
            // Protocol v1 and existing inventory consumers used this key. Keep it during
            // the split-controller retirement even though the value now identifies onec.exe.
            "onec_ops_executable": onec_executable.as_deref(),
            "gateway_primary": gateway_primary,
            "gateways": gateway_routes,
            "remote_port": server.remote_port,
        }),
        Ok(other) => json!({
            "name": server.name,
            "source": source,
            "persistence_mode_source": "hub_enrollment",
            "persistence_mode": server.persistence_mode,
            "gateway_primary": gateway_primary,
            "gateways": gateway_routes,
            "error": format!("unexpected hello response: {other:?}"),
        }),
        Err(_) => {
            json!({
                "name": server.name,
                "source": source,
                "persistence_mode_source": "hub_enrollment",
                "persistence_mode": server.persistence_mode,
                "recovery_hint": recovery_hint(&server),
                "gateway_primary": gateway_primary,
                "gateways": gateway_routes,
                "remote_port": server.remote_port,
            })
        }
    };
    if let Some(label) = display_name {
        row["display_name"] = json!(label);
    }
    if let (Some(row), Some(fields)) = (row.as_object_mut(), status_fields.as_object()) {
        row.extend(fields.clone());
    }
    Ok(row)
}

pub(super) async fn remove(name: String) -> AppResult<()> {
    let config_path = hub_config_path()?;
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink controller config {}",
            config_path.display()
        ))
    })?;
    let agent = hub
        .resolve_agent(&name)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {name:?}")))?;
    hub.remove_agent(&agent).await?;
    println!("Revoked managed host {}", agent.name);
    Ok(())
}

pub(super) async fn info(name: String) -> AppResult<()> {
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error("hostlink controller is not configured".to_owned())
    })?;
    let agent = hub
        .resolve_agent(&name)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {name:?}")))?;
    let server = resolve_remote_server(&agent.machine_id).await?;
    let response = RemoteAgentClient::new(server.clone())?.hello().await?;
    let agent_name = match &response {
        AgentResponseKind::Hello {
            name: agent_name, ..
        } => agent_name,
        _ => {
            return Err(crate::invalid_config(
                "remote agent returned a non-hello response during inspection".to_owned(),
            ));
        }
    };
    let identity_mismatch = hello_identity_status(&server.name, agent_name).0 != "online";
    let status_observation = if identity_mismatch {
        "authenticated_hello_identity_mismatch"
    } else {
        "authenticated_hello"
    };
    let observed_at = observed_at_unix_ms();
    let (gateways, gateway_primary) = gateway_inventory(&server);
    let mut report = json!({
        "agent": &response,
        "status_observation": status_observation,
        "observed_at_unix_ms": observed_at,
        "status_scope": "point_in_time",
        "status_note": if identity_mismatch {
            "Authenticated Hello responded, but the agent name does not match the selected managed host."
        } else {
            HELLO_POINT_IN_TIME_NOTE
        },
        "persistence_mode_source": "hub_enrollment",
        "persistence_mode": server.persistence_mode,
        "gateway_primary": gateway_primary,
        "gateways": gateways,
    });
    if let Some(label) = agent.display_name {
        report["display_name"] = json!(label);
    }
    if identity_mismatch {
        report["identity_match"] = json!(false);
    }
    crate::cli::output::print_pretty_json(&report);
    require_hello_identity_match(&server.name, agent_name)?;
    Ok(())
}

pub(super) async fn verify(name: String, json_output: bool) -> AppResult<()> {
    let server = resolve_remote_server(&name).await?;
    let client = RemoteAgentClient::new(server.clone())?;
    let hello = client.hello().await?;
    let AgentResponseKind::Hello {
        name: agent_name,
        hostname,
        ..
    } = hello
    else {
        return Err(crate::invalid_config(
            "remote agent returned a non-hello response during verification".to_owned(),
        ));
    };
    let observed_at = observed_at_unix_ms();
    let (status, status_observation) = hello_identity_status(&server.name, &agent_name);
    let identity_match = status == "online";
    let (gateways, gateway_primary) = gateway_inventory(&server);
    let report = json!({
        "name": &server.name,
        "status": if identity_match { "ok" } else { "identity_mismatch" },
        "status_observation": status_observation,
        "observed_at_unix_ms": observed_at,
        "status_scope": "point_in_time",
        "status_note": if identity_match {
            HELLO_POINT_IN_TIME_NOTE
        } else {
            "Authenticated Hello responded, but the agent name does not match the selected managed host."
        },
        "persistence_mode_source": "hub_enrollment",
        "persistence_mode": &server.persistence_mode,
        "agent_name": &agent_name,
        "hostname": &hostname,
        "identity_match": identity_match,
        "gateway_primary": &gateway_primary,
        "gateways": &gateways,
        "remote_port": server.remote_port,
    });
    if json_output {
        crate::cli::output::print_pretty_json(&report);
    } else {
        if identity_match {
            println!("Managed host {name}: OK");
            println!("{HELLO_POINT_IN_TIME_NOTE}");
        } else {
            println!("Managed host {name}: IDENTITY MISMATCH");
            println!(
                "Authenticated Hello responded, but the agent name does not match the selected managed host."
            );
        }
        println!("Agent: {agent_name} @ {hostname}");
        println!(
            "Primary gateway: {}",
            gateway_primary.as_deref().unwrap_or("unknown")
        );
        println!("Approved gateways: {}", gateways.len());
        println!(
            "Tunnel: {} -> 127.0.0.1:{}",
            gateway_primary.as_deref().unwrap_or("unknown"),
            server.remote_port
        );
        if !identity_match {
            println!("Warning: agent identity {agent_name:?} does not match selector {name:?}");
        }
    }
    require_hello_identity_match(&server.name, &agent_name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn inventory_hello_probes_keep_two_connection_cap_and_preserve_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let probes = (0..12).map(|index| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(if index % 4 == 0 {
                    35
                } else {
                    10
                }))
                .await;
                active.fetch_sub(1, Ordering::SeqCst);
                let name = format!("ExampleAgent{index}");
                let hello = Ok(AgentResponseKind::Hello {
                    name: name.clone(),
                    agent_version: "1.0.0".to_owned(),
                    hostname: format!("example-host-{index}"),
                    os: "windows".to_owned(),
                    capabilities: vec![],
                    agent_executable: None,
                    onec_executable: None,
                });
                Ok(inventory_status_fields(
                    &hello,
                    RemoteCarrier::TargetSsh,
                    &name,
                    Some(index),
                ))
            }
        });

        let actual = probe_in_order(probes, MAX_HELLO_PROBES)
            .await
            .expect("bounded inventory probes");
        assert_eq!(actual.len(), 12);
        assert!(actual.iter().all(|row| row["status"] == "online"));
        assert!(actual.iter().all(|row| row["identity_match"] == true));
        assert_eq!(
            actual
                .iter()
                .map(|row| row["observed_at_unix_ms"].as_u64())
                .collect::<Vec<_>>(),
            (0..12).map(Some).collect::<Vec<_>>(),
            "completed rows retain the sorted input order"
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), MAX_HELLO_PROBES);
        assert!(peak.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn inventory_route_resolution_is_bounded_but_can_exceed_hello_cap() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let probes = (0..12).map(|index| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(index)
            }
        });

        let actual = probe_in_order(probes, MAX_HUB_ROUTE_RESOLUTIONS)
            .await
            .expect("bounded route resolutions");
        assert_eq!(actual, (0..12).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), MAX_HUB_ROUTE_RESOLUTIONS);
        assert!(peak.load(Ordering::SeqCst) > MAX_HELLO_PROBES);
    }

    #[tokio::test]
    async fn inventory_slow_host_does_not_serialize_healthy_hello_probes() {
        let completed_healthy = Arc::new(AtomicUsize::new(0));
        let completed_for_probes = Arc::clone(&completed_healthy);
        let probes = (0..12).map(move |index| {
            let completed_healthy = Arc::clone(&completed_for_probes);
            async move {
                if index == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    return Ok(inventory_status_fields(
                        &Err(crate::invalid_config("hello timed out".to_owned())),
                        RemoteCarrier::TargetSsh,
                        "ExampleAgent0",
                        Some(1),
                    ));
                }
                let hello = Ok(AgentResponseKind::Hello {
                    name: format!("ExampleAgent{index}"),
                    agent_version: "1.0.0".to_owned(),
                    hostname: format!("example-host-{index}"),
                    os: "windows".to_owned(),
                    capabilities: vec![],
                    agent_executable: None,
                    onec_executable: None,
                });
                completed_healthy.fetch_add(1, Ordering::SeqCst);
                Ok(inventory_status_fields(
                    &hello,
                    RemoteCarrier::TargetSsh,
                    &format!("ExampleAgent{index}"),
                    Some(1),
                ))
            }
        });

        let task = tokio::spawn(probe_in_order(probes, MAX_HELLO_PROBES));
        tokio::time::timeout(std::time::Duration::from_millis(150), async {
            while completed_healthy.load(Ordering::SeqCst) < 11 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("healthy Hello probes should complete while one host is slow");
        assert!(
            !task.is_finished(),
            "the deliberately slow host is still pending"
        );

        let actual = task
            .await
            .expect("inventory probe task")
            .expect("all host observations");
        assert_eq!(actual.len(), 12);
        assert_eq!(completed_healthy.load(Ordering::SeqCst), 11);
        assert_eq!(actual[0]["status"], "unknown");
        assert!(actual[1..].iter().all(|row| row["status"] == "online"));
        assert!(actual[1..].iter().all(|row| row["identity_match"] == true));
    }

    #[test]
    fn inventory_route_resolution_failure_is_unknown_not_online() {
        let row =
            route_resolution_failure_row("ExampleAgent", "hub-target-ssh", Some("Example display"));
        assert_eq!(row["status"], "unknown");
        assert_eq!(row["status_observation"], "route_resolution_failed");
        assert_eq!(row["display_name"], "Example display");
        assert_ne!(row["status"], "online");
    }

    #[tokio::test]
    async fn inventory_probe_failure_does_not_return_partial_inventory() {
        let probes = (0..8).map(|index| async move {
            if index == 1 {
                return Err(crate::invalid_config("probe rejected".to_owned()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            Ok(index)
        });
        let error = probe_in_order(probes, MAX_HELLO_PROBES)
            .await
            .expect_err("one failed probe");
        assert!(error.to_string().contains("probe rejected"));
    }

    #[test]
    fn regression_inv_216_hello_identity_mismatch_is_not_reported_healthy() {
        // Deterministic evidence: a typed Hello response, then a later gateway transport
        // failure whose payload contains host details that must not enter inventory output.
        let hello = Ok(AgentResponseKind::Hello {
            name: "ExampleAgent".to_owned(),
            agent_version: "1.0.0".to_owned(),
            hostname: "example-host".to_owned(),
            os: "windows".to_owned(),
            capabilities: vec!["exec.bounded-v1".to_owned()],
            agent_executable: None,
            onec_executable: None,
        });
        let hello_observation = inventory_status_fields(
            &hello,
            RemoteCarrier::TargetSsh,
            "ExampleAgent",
            Some(1_792_000_000_000),
        );
        assert_eq!(
            hello_observation,
            json!({
                "status": "online",
                "status_observation": "authenticated_hello",
                "observed_at_unix_ms": 1_792_000_000_000_u64,
                "status_scope": "point_in_time",
                "status_note": HELLO_POINT_IN_TIME_NOTE,
                "identity_match": true,
            })
        );

        let mismatched_identity = inventory_status_fields(
            &hello,
            RemoteCarrier::TargetSsh,
            "ExampleDifferentAgent",
            Some(1_792_000_000_000),
        );
        assert_eq!(
            mismatched_identity,
            json!({
                "status": "identity_mismatch",
                "status_observation": "authenticated_hello_identity_mismatch",
                "observed_at_unix_ms": 1_792_000_000_000_u64,
                "status_scope": "point_in_time",
                "status_note": "Authenticated Hello responded, but the agent name does not match the selected managed host.",
                "identity_match": false,
            })
        );
        assert_eq!(
            hello_identity_status("ExampleAgent", "exampleagent"),
            ("online", "authenticated_hello")
        );
        assert!(require_hello_identity_match("ExampleAgent", "exampleagent").is_ok());
        assert_eq!(
            hello_identity_status("ExampleAgent", "ExampleDifferentAgent"),
            ("identity_mismatch", "authenticated_hello_identity_mismatch")
        );
        let mismatch_error = require_hello_identity_match("ExampleAgent", "ExampleDifferentAgent")
            .expect_err("mismatched Hello identity must fail the CLI command");
        assert!(
            mismatch_error
                .downcast_ref::<HelloIdentityMismatch>()
                .is_some()
        );
        assert_eq!(
            mismatch_error.to_string(),
            "authenticated Hello identity does not match the selected managed host"
        );
        assert!(!mismatch_error.to_string().contains("ExampleAgent"));
        assert!(!mismatch_error.to_string().contains("ExampleDifferentAgent"));
        let later_channel_failure = Err(crate::invalid_config(
            "gateway[3].gateway_connect timeout=5s host=192.0.2.7 private=/operator/ssh/key"
                .to_owned(),
        ));
        let failed_observation = inventory_status_fields(
            &later_channel_failure,
            RemoteCarrier::TargetSsh,
            "ExampleAgent",
            Some(1_792_000_005_000),
        );
        assert_eq!(
            failed_observation,
            json!({
                "status": "unknown",
                "status_observation": "hello_transport_failed",
                "observed_at_unix_ms": 1_792_000_005_000_u64,
                "status_scope": "transport_attempt",
                "failure_phase": "gateway_connect",
                "error": "gateway_connect: Hello transport failed; agent state is unknown. Check this route phase and retry.",
            })
        );
        let serialized = failed_observation.to_string();
        assert!(!serialized.contains("192.0.2.7"));
        assert!(!serialized.contains("/operator/ssh/key"));

        let malformed_hello = inventory_status_fields(
            &Ok(AgentResponseKind::Exec {
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
                stdout_base64: None,
                stderr_base64: None,
                result_set: None,
            }),
            RemoteCarrier::TargetSsh,
            "ExampleAgent",
            Some(1_792_000_000_000),
        );
        assert_eq!(malformed_hello["status"], "unknown");
        assert_ne!(malformed_hello["status"], "online");

        for (error, expected_phase) in [
            (
                "gateway[0].gateway_direct_tcpip timeout",
                "gateway_direct_tcpip",
            ),
            ("gateway[1].gateway_connect failed", "gateway_connect"),
            (
                "gateway[0].gateway_connect failed; gateway[1].gateway_direct_tcpip timeout",
                "gateway_connect",
            ),
            ("target_ssh_handshake timeout", "target_ssh_handshake"),
            ("target_ssh_auth failed", "target_ssh_auth"),
            ("agent_control timeout", "agent_control"),
            ("target_direct_tcpip failed", "target_direct_tcpip"),
            (
                "opening gateway direct-tcpip channel",
                "gateway_direct_tcpip",
            ),
            (
                "connecting to target SSH host alias",
                "target_ssh_handshake",
            ),
            ("all approved gateway routes failed", "gateway_connect"),
        ] {
            assert_eq!(transport_failure_phase(error), expected_phase, "{error}");
        }
        assert_eq!(failure_status(RemoteCarrier::GatewayControl), "unknown");
        assert_eq!(failure_status(RemoteCarrier::TargetSsh), "unknown");
    }
}
