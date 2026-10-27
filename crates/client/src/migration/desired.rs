use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

use super::{
    HostReadiness, block,
    paths::{require_owned_path, string_field, valid_host_pin},
};

pub(super) fn inspect_desired_agent(value: &Value, config_path: &Path, report: &mut HostReadiness) {
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

pub(super) fn inspect_desired_host(value: &Value, config_path: &Path, report: &mut HostReadiness) {
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

pub(super) fn compare_gateway_pair(agent: &Value, host: &Value, report: &mut HostReadiness) {
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
