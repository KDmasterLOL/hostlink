//! Stable agent naming and remote-port allocation/probing.

use super::*;
use std::net::TcpListener;

pub(super) fn assign_name(
    state: &HubState,
    machine_id: &str,
    requested: &str,
) -> io::Result<String> {
    validate_identifier("name", requested, 128)?;
    let is_available = |candidate: &str| {
        state.agents.values().all(|record| {
            record.machine_id == machine_id || !record.name.eq_ignore_ascii_case(candidate)
        })
    };
    if is_available(requested) {
        return Ok(requested.to_owned());
    }

    let machine_prefix = machine_id.chars().take(8).collect::<String>();
    let other_agent_count = state
        .agents
        .values()
        .filter(|record| record.machine_id != machine_id)
        .count();
    // There are at most `other_agent_count` occupied names, so one more
    // distinct candidate must be free unless the state has inconsistent names.
    for suffix_number in 1..=other_agent_count.saturating_add(1) {
        let suffix = if suffix_number == 1 {
            format!("-{machine_prefix}")
        } else {
            format!("-{machine_prefix}-{suffix_number}")
        };
        let base_length = 128_usize.saturating_sub(suffix.len());
        let base = requested.chars().take(base_length).collect::<String>();
        let candidate = format!("{base}{suffix}");
        validate_identifier("name", &candidate, 128)?;
        if is_available(&candidate) {
            return Ok(candidate);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("could not assign a unique name for machine_id {machine_id:?}"),
    ))
}

pub(super) fn allocate_port(state: &HubState, config: &HubConfig) -> io::Result<u16> {
    if config.probe_gateway_ports_locally {
        allocate_port_with_probe(state, config, gateway_port_available)
    } else {
        allocate_port_with_probe(state, config, |_| Ok(true))
    }
}

pub(super) fn allocate_port_with_probe<F>(
    state: &HubState,
    config: &HubConfig,
    mut is_available: F,
) -> io::Result<u16>
where
    F: FnMut(u16) -> io::Result<bool>,
{
    for port in config.port_from..=config.port_to {
        if config.reserved_ports.contains(&port)
            || state
                .agents
                .values()
                .any(|record| record.remote_port == port)
        {
            continue;
        }
        if is_available(port)? {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "HostLink Hub remote-port pool is exhausted",
    ))
}

pub(super) fn gateway_port_available(port: u16) -> io::Result<bool> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            drop(listener);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(false),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("failed to probe gateway loopback port {port}: {error}"),
        )),
    }
}
