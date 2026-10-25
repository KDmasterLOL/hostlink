//! Offline, read-only inspection of legacy HostLink snapshots and an explicit
//! russh Agent/HostSpec pair. This module never connects or writes files.

use serde::Serialize;
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;

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
            host.review.push(
                "verify desired Agent gateway pin file matches the HostSpec gateway pin".into(),
            );
            host.review.push("verify target Agent public pin against the installed host key on the disposable target".into());
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    host: String,
    user: String,
    port: u64,
}

fn old_hub_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
    let routes = if let Some(items) = value
        .get("gateways")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
    {
        items.iter().filter_map(route_object).collect()
    } else if let Some(host) = string_field(value, "gateway_host") {
        let user = string_field(value, "agent_ssh_user").unwrap_or_default();
        vec![Route {
            host,
            user,
            port: value
                .get("gateway_ssh_port")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| {
                    block(report, "legacy Hub gateway port is not explicit");
                    0
                }),
        }]
    } else {
        block(report, "legacy Hub has no supported gateway route");
        Vec::new()
    };
    if routes
        .iter()
        .any(|route| route.user.is_empty() || route.port == 0)
    {
        block(report, "legacy Hub gateway route is incomplete");
    }
    routes
}

fn inspect_old_hub_pins(value: &Value, report: &mut HostReadiness) {
    let pins: Vec<Option<String>> = if let Some(gateways) = value
        .get("gateways")
        .and_then(Value::as_array)
        .filter(|gateways| !gateways.is_empty())
    {
        gateways
            .iter()
            .map(|gateway| string_field(gateway, "host_public_key"))
            .collect()
    } else {
        vec![string_field(value, "gateway_host_public_key")]
    };
    if pins.is_empty()
        || pins
            .iter()
            .any(|pin| pin.as_deref().is_none_or(|pin| !valid_host_pin(pin)))
    {
        block(
            report,
            "legacy Hub gateway public-key pin is missing or invalid",
        );
    }
}

fn old_controller_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
    let routes = if let Some(items) = value.get("gateways").and_then(Value::as_array) {
        items.iter().filter_map(route_object).collect()
    } else if let Some(host) = string_field(value, "gateway_host") {
        vec![Route {
            host,
            user: string_field(value, "gateway_user").unwrap_or_default(),
            port: value
                .get("gateway_port")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| {
                    block(report, "legacy Controller gateway port is not explicit");
                    0
                }),
        }]
    } else {
        block(report, "legacy Controller has no explicit gateway route");
        Vec::new()
    };
    if routes
        .iter()
        .any(|route| route.user.is_empty() || route.port == 0)
    {
        block(report, "legacy Controller gateway route is incomplete");
    }
    routes
}

fn old_agent_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
    let Some(ssh) = value.get("ssh").filter(|value| !value.is_null()) else {
        block(report, "legacy Agent has no supported reverse SSH route");
        return Vec::new();
    };
    if string_field(ssh, "identity").is_none() || string_field(ssh, "known_hosts").is_none() {
        block(
            report,
            "legacy Agent reverse route lacks explicit SSH key or gateway trust",
        );
    }
    if let Some(items) = ssh.get("gateways").and_then(Value::as_array) {
        items.iter().filter_map(route_object).collect()
    } else if let Some(host) = string_field(ssh, "gateway_host") {
        vec![Route {
            host,
            user: string_field(ssh, "gateway_user").unwrap_or_default(),
            port: ssh
                .get("gateway_port")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| {
                    block(report, "legacy Agent gateway port is not explicit");
                    0
                }),
        }]
    } else {
        block(
            report,
            "legacy Agent route schema is unsupported or ambiguous",
        );
        Vec::new()
    }
}

fn route_object(value: &Value) -> Option<Route> {
    Some(Route {
        host: string_field(value, "host")?,
        user: string_field(value, "user")?,
        port: value.get("port").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn has_tls_proxy(value: &Value) -> bool {
    value
        .get("ssh")
        .and_then(|v| v.get("tls_proxy"))
        .is_some_and(|v| !v.is_null())
        || value
            .get("ssh")
            .and_then(|v| v.get("gateways"))
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|v| v.get("tls_proxy").is_some_and(|p| !p.is_null()))
            })
        || value.get("tls_proxy").is_some_and(|v| !v.is_null())
        || value
            .get("gateways")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|v| v.get("tls_proxy").is_some_and(|p| !p.is_null()))
            })
}

fn inspect_desired_agent(value: &Value, config_path: &Path, report: &mut HostReadiness) {
    let Some(listen) = string_field(value, "listen") else {
        block(report, "desired Agent listen address is missing");
        return;
    };
    match listen.parse::<SocketAddr>() {
        Ok(address) if !address.ip().is_loopback() || address.port() == 0 => {
            block(
                report,
                "desired Agent listener must be loopback with a nonzero port",
            );
        }
        Err(_) => block(report, "desired Agent listener is invalid"),
        _ => {}
    }
    for name in ["host_key", "authorized_keys"] {
        require_owned_path(value, name, config_path, true, report);
    }
    require_owned_path(value, "jobs_root", config_path, false, report);
    if string_field(value, "user").is_none() {
        block(report, "desired Agent SSH user is missing");
    }
    report.review.push(
        "verify the new Controller public key is present in the desired Agent authorized keys"
            .into(),
    );
    if let Some(gateway) = value.get("gateway").filter(|v| !v.is_null()) {
        for name in ["identity", "host_public_key"] {
            require_owned_path(gateway, name, config_path, true, report);
        }
        if gateway
            .get("remote_port")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
        {
            block(
                report,
                "desired Agent reverse gateway port is missing or zero",
            );
        }
    }
}

fn inspect_desired_host(value: &Value, config_path: &Path, report: &mut HostReadiness) {
    if string_field(value, "host_public_key").is_none_or(|pin| !valid_host_pin(&pin)) {
        block(
            report,
            "desired HostSpec requires an explicit valid SSH host pin",
        );
    }
    require_owned_path(value, "identity", config_path, true, report);
    if string_field(value, "user").is_none() {
        block(report, "desired HostSpec SSH user is missing");
    }
    if string_field(value, "endpoint")
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .is_none()
    {
        block(report, "desired HostSpec endpoint is missing or invalid");
    }
    if let Some(gateway) = value.get("gateway").filter(|v| !v.is_null()) {
        if string_field(gateway, "host_public_key").is_none_or(|pin| !valid_host_pin(&pin)) {
            block(
                report,
                "desired gateway requires an explicit valid SSH host pin",
            );
        }
        require_owned_path(gateway, "identity", config_path, true, report);
        if gateway
            .get("reverse_port")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == 0
        {
            block(report, "desired gateway reverse port is missing or zero");
        }
    }
}

fn compare_gateway_pair(agent: &Value, host: &Value, report: &mut HostReadiness) {
    if string_field(agent, "user") != string_field(host, "user") {
        block(report, "desired Agent and HostSpec gateway user differs");
    }
    let reverse = agent.get("remote_port").and_then(Value::as_u64);
    let host_reverse = host.get("reverse_port").and_then(Value::as_u64);
    if reverse != host_reverse {
        block(report, "desired Agent and HostSpec reverse ports differ");
    }
    if string_field(agent, "identity") != string_field(host, "identity") {
        block(
            report,
            "desired Agent and HostSpec gateway identity paths differ",
        );
    }
}

fn valid_host_pin(pin: &str) -> bool {
    let fields: Vec<_> = pin.split_ascii_whitespace().collect();
    if !(2..=3).contains(&fields.len()) {
        return false;
    }
    if !fields[0].starts_with("ssh-") && !fields[0].starts_with("ecdsa-") {
        return false;
    }
    russh::keys::parse_public_key_base64(fields[1])
        .is_ok_and(|key| key.algorithm().to_string() == fields[0])
}

fn require_owned_path(
    value: &Value,
    field: &str,
    config: &Path,
    regular_file: bool,
    report: &mut HostReadiness,
) {
    let Some(path) = string_field(value, field) else {
        block(
            report,
            if field == "jobs_root" {
                "desired Agent jobs root is missing"
            } else {
                "required desired key path is missing"
            },
        );
        return;
    };
    let path = PathBuf::from(path);
    let resolved = if path.is_absolute() {
        path
    } else {
        config.parent().unwrap_or(Path::new(".")).join(path)
    };
    if has_symlink_component(&resolved) {
        block(report, "required desired path traverses a symlink");
        return;
    }
    let metadata = match fs::symlink_metadata(&resolved) {
        Ok(metadata) if !metadata.file_type().is_symlink() => metadata,
        _ => {
            block(
                report,
                "required desired path is missing, unreadable, or a symlink",
            );
            return;
        }
    };
    if (regular_file && !metadata.is_file()) || (!regular_file && !metadata.is_dir()) {
        block(report, "required desired path has the wrong file type");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            block(report, "desired path is not owned by the preflight user");
        }
        if regular_file && metadata.mode() & 0o077 != 0 {
            block(
                report,
                "desired private key file permissions are broader than owner-only",
            );
        } else if !regular_file && metadata.mode() & 0o077 != 0 {
            block(
                report,
                "desired Agent root permissions are broader than owner-only",
            );
        }
    }
    #[cfg(windows)]
    if !regular_file {
        report
            .review
            .push("desired Agent root owner and ACL must be verified on Windows".into());
    }
}

fn has_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

fn read_json(path: &Path) -> Result<Value, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cannot read supplied snapshot")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("supplied snapshots must be bounded regular files, not symlinks");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|_| "cannot read supplied snapshot")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot read supplied snapshot")?;
    if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err("supplied snapshots must be bounded regular files");
    }
    read_json_file(file)
}

fn read_json_file(mut file: File) -> Result<Value, &'static str> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read supplied snapshot")?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err("supplied snapshot exceeds the size limit");
    }
    serde_json::from_slice(&bytes).map_err(|_| "supplied snapshot is not valid JSON")
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

fn block(report: &mut HostReadiness, reason: &str) {
    report.blockers.push(reason.to_owned());
}
