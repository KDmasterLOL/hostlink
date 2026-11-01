//! Offline inspection of legacy snapshots and explicit russh configuration.

mod desired;
mod legacy;
mod paths;

use serde::Serialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

use desired::{compare_gateway_pair, inspect_desired_agent, inspect_desired_host};
use legacy::{
    block, has_tls_proxy, inspect_old_hub_pins, old_agent_gateways, old_controller_gateways,
    old_hub_gateways,
};
use paths::{read_json, string_field};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Readiness {
    Ready,
    Review,
    Blocked,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HostReadiness {
    pub host: String,
    pub readiness: Readiness,
    pub blockers: Vec<String>,
    pub review: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub version: u8,
    pub hosts: Vec<HostReadiness>,
    pub writes_performed: bool,
    pub network_attempted: bool,
}

/// Inspect the five explicitly supplied snapshots/configs. Error messages are
/// intentionally generic so malformed JSON and I/O errors cannot echo secrets.
pub fn preflight(
    old_hub: &Path,
    old_controller: &Path,
    old_agent: &Path,
    new_agent: &Path,
    new_host: &Path,
) -> Result<MigrationReport, &'static str> {
    let hub = read_json(old_hub)?;
    let controller = read_json(old_controller)?;
    let agent = read_json(old_agent)?;
    let desired_agent = read_json(new_agent)?;
    let desired_host = read_json(new_host)?;

    let mut host = HostReadiness {
        host: "host-001".to_owned(),
        readiness: Readiness::Ready,
        blockers: Vec::new(),
        review: Vec::new(),
    };

    let hub_gateways = old_hub_gateways(&hub, &mut host);
    let controller_gateways = old_controller_gateways(&controller, &mut host);
    let agent_gateways = old_agent_gateways(&agent, &mut host);
    inspect_old_hub_pins(&hub, &mut host);
    if hub_gateways.len() > 1 || controller_gateways.len() > 1 || agent_gateways.len() > 1 {
        block(
            &mut host,
            "multiple legacy gateways require manual route selection",
        );
    }
    let mut legacy_ports: Vec<u64> = hub_gateways.iter().map(|route| route.port).collect();
    legacy_ports.sort_unstable();
    if legacy_ports.windows(2).any(|ports| ports[0] == ports[1]) {
        block(&mut host, "legacy gateway routes reuse a port");
    }
    if hub_gateways
        .first()
        .zip(controller_gateways.first())
        .is_some_and(|(hub, controller)| hub.host != controller.host || hub.port != controller.port)
        || hub_gateways.is_empty()
        || controller_gateways.is_empty()
    {
        block(
            &mut host,
            "legacy Hub and Controller routes do not match exactly",
        );
    }
    if let (Some(old), Some(agent_route)) = (hub_gateways.first(), agent_gateways.first())
        && (old.host != agent_route.host
            || old.user != agent_route.user
            || old.port != agent_route.port)
    {
        block(
            &mut host,
            "legacy Agent reverse route does not match the Hub gateway",
        );
    }

    if has_tls_proxy(&agent) || has_tls_proxy(&hub) {
        block(
            &mut host,
            "legacy TLS proxy has no implicit russh equivalent",
        );
    }
    if string_field(&controller, "identity").is_none() {
        block(
            &mut host,
            "legacy Controller has no explicit SSH identity path",
        );
    }
    if string_field(&controller, "known_hosts").is_none() {
        block(
            &mut host,
            "legacy Controller has no explicit gateway trust file",
        );
    }
    let controller_identity = string_field(&controller, "identity");
    let token_file = string_field(&controller, "token_file");
    let token_env = string_field(&controller, "token_env");
    if controller_identity.as_ref().is_some_and(|identity| {
        token_file.as_ref() == Some(identity) || token_env.as_ref() == Some(identity)
    }) {
        block(
            &mut host,
            "legacy Hub API token is not an SSH authentication credential",
        );
    }
    if agent.get("ssh_server").is_some_and(|v| !v.is_null()) {
        host.review
            .push("legacy external sshd ownership requires operator review".into());
    }

    inspect_desired_agent(&desired_agent, new_agent, &mut host);
    inspect_desired_host(&desired_host, new_host, &mut host);
    if !hub_gateways.is_empty()
        && (desired_agent.get("gateway").is_none_or(Value::is_null)
            || desired_host.get("gateway").is_none_or(Value::is_null))
    {
        block(
            &mut host,
            "desired Agent and HostSpec must explicitly preserve the legacy gateway route",
        );
    }
    if let (Some(old_listen), Some(new_listen)) = (
        string_field(&agent, "listen"),
        string_field(&desired_agent, "listen"),
    ) && old_listen
        .parse::<SocketAddr>()
        .ok()
        .zip(new_listen.parse::<SocketAddr>().ok())
        .is_some_and(|(old, new)| old.port() == new.port())
    {
        block(
            &mut host,
            "side-by-side Agent listener reuses the legacy control port",
        );
    }
    match (desired_agent.get("gateway"), desired_host.get("gateway")) {
        (Some(Value::Object(_)), Some(Value::Object(_))) => {
            compare_gateway_pair(
                desired_agent
                    .get("gateway")
                    .expect("matched gateway object"),
                desired_host.get("gateway").expect("matched gateway object"),
                &mut host,
            );
            // Gateway mode opens 127.0.0.1:reverse_port via the authenticated
            // gateway channel, regardless of HostSpec.endpoint. Reject a
            // contradictory explicit endpoint rather than report it ready.
            if let (Some(port), Some(endpoint)) = (
                desired_host
                    .get("gateway")
                    .and_then(|value| value.get("reverse_port"))
                    .and_then(Value::as_u64),
                string_field(&desired_host, "endpoint")
                    .and_then(|text| text.parse::<SocketAddr>().ok()),
            ) && (endpoint.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || u64::from(endpoint.port()) != port)
            {
                block(
                    &mut host,
                    "desired HostSpec endpoint must describe the loopback reverse gateway port",
                );
            }
            host.review.push(
                "verify desired Agent gateway pin file matches the HostSpec gateway pin".into(),
            );
            host.review.push("verify target Agent public pin against the installed host key on the disposable target".into());
            host.review.push(
                "verify distinct Agent and Controller gateway SSH identities are independently authorized".into(),
            );
        }
        (None | Some(Value::Null), None | Some(Value::Null)) => {}
        _ => block(
            &mut host,
            "desired Agent and HostSpec gateway topology differs",
        ),
    }
    if let Some(old_route) = hub_gateways.first()
        && let Some(new_gateway) = desired_agent
            .get("gateway")
            .filter(|value| !value.is_null())
    {
        if string_field(new_gateway, "host").as_deref() != Some(old_route.host.as_str())
            || string_field(new_gateway, "user").as_deref() != Some(old_route.user.as_str())
            || new_gateway.get("port").and_then(Value::as_u64) != Some(old_route.port)
        {
            block(
                &mut host,
                "desired Agent gateway does not match the explicit legacy route",
            );
        }
        if old_route.host.parse::<std::net::IpAddr>().is_err() {
            host.review.push(
                "confirm the explicitly configured gateway address resolves to the legacy gateway"
                    .into(),
            );
        } else if string_field(
            desired_host.get("gateway").unwrap_or(&Value::Null),
            "address",
        )
        .and_then(|address| address.parse::<SocketAddr>().ok())
        .is_none_or(|address| {
            address.ip().to_string() != old_route.host
                || u64::from(address.port()) != old_route.port
        }) {
            block(
                &mut host,
                "desired HostSpec gateway socket does not match the legacy gateway route",
            );
        }
    }

    if string_field(&agent, "jobs_dir").is_some() {
        host.review
            .push("legacy per-host process root requires target-side owner verification".into());
    }
    if host.blockers.is_empty() && !host.review.is_empty() {
        host.readiness = Readiness::Review;
    } else if !host.blockers.is_empty() {
        host.readiness = Readiness::Blocked;
    }
    host.blockers.sort();
    host.blockers.dedup();
    host.review.sort();
    host.review.dedup();

    Ok(MigrationReport {
        version: 1,
        hosts: vec![host],
        writes_performed: false,
        network_attempted: false,
    })
}
