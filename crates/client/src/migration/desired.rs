use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

use super::{
    HostReadiness, block,
    paths::{require_owned_path, string_field, valid_host_pin},
};

pub(super) fn inspect_desired_agent(value: &Value, config_path: &Path, report: &mut HostReadiness) {
    if value
        .get("gateway_alternates")
        .is_some_and(|routes| !matches!(routes, Value::Array(routes) if routes.is_empty()))
    {
        block(
            report,
            "desired Agent multiple or malformed gateway alternates are unsupported by one-route preflight",
        );
    }
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
        if string_field(gateway, "host").is_none()
            || !gateway
                .get("port")
                .and_then(Value::as_u64)
                .is_some_and(|port| (1..=65535).contains(&port))
        {
            block(
                report,
                "desired Agent gateway endpoint is missing or invalid",
            );
        }
        if string_field(gateway, "user").is_none() {
            block(report, "desired Agent gateway SSH user is missing");
        }
        for name in ["identity", "host_public_key"] {
            require_owned_path(gateway, name, config_path, true, report);
        }
        if gateway
            .get("remote_port")
            .and_then(Value::as_u64)
            .is_none_or(|port| !(1..=65535).contains(&port))
        {
            block(
                report,
                "desired Agent reverse gateway port is missing or invalid",
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
        .is_none_or(|endpoint| endpoint.port() == 0)
    {
        block(report, "desired HostSpec endpoint is missing or invalid");
    }
    if let Some(gateway) = value.get("gateway").filter(|v| !v.is_null()) {
        if gateway
            .get("alternates")
            .is_some_and(|routes| !matches!(routes, Value::Array(routes) if routes.is_empty()))
        {
            block(
                report,
                "desired HostSpec multiple or malformed gateway alternates are unsupported by one-route preflight",
            );
        }
        if string_field(gateway, "user").is_none() {
            block(report, "desired HostSpec gateway SSH user is missing");
        }
        if string_field(gateway, "address")
            .and_then(|s| s.parse::<SocketAddr>().ok())
            .is_none_or(|address| address.port() == 0)
        {
            block(
                report,
                "desired HostSpec gateway address is missing or invalid",
            );
        }
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
            .is_none_or(|port| !(1..=65535).contains(&port))
        {
            block(report, "desired gateway reverse port is missing or invalid");
        }
    }
}

pub(super) fn compare_gateway_pair(agent: &Value, host: &Value, report: &mut HostReadiness) {
    if string_field(agent, "user") != string_field(host, "user") {
        // A gateway may authorize two different SSH users for reverse tunnel
        // and Controller access. The offline inspector cannot prove either
        // server-side authorization, so report a human check instead.
        report
            .review
            .push("verify separately authorized Agent and Controller gateway SSH users".into());
    }
    let reverse = agent.get("remote_port").and_then(Value::as_u64);
    let host_reverse = host.get("reverse_port").and_then(Value::as_u64);
    if reverse != host_reverse {
        block(report, "desired Agent and HostSpec reverse ports differ");
    }
    // ReverseGateway.identity belongs to the Agent; GatewayHop.identity
    // belongs to the Controller. Their private key paths must not be equated.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::Readiness;
    use serde_json::json;

    fn report() -> HostReadiness {
        HostReadiness {
            host: "host-001".into(),
            readiness: Readiness::Ready,
            blockers: Vec::new(),
            review: Vec::new(),
        }
    }

    #[test]
    fn separate_gateway_credentials_and_accounts_require_review_not_false_mismatch() {
        let agent = json!({
            "user": "reverse-agent", "remote_port": 23000,
            "identity": "/private/agent-gateway-key"
        });
        let controller = json!({
            "user": "operator", "reverse_port": 23000,
            "identity": "/private/controller-gateway-key"
        });
        let mut report = report();
        compare_gateway_pair(&agent, &controller, &mut report);
        assert!(report.blockers.is_empty(), "{:?}", report.blockers);
        assert!(
            report
                .review
                .iter()
                .any(|s| s.contains("separately authorized"))
        );
        assert!(report.review.iter().all(|s| !s.contains("private/")));
    }

    #[test]
    fn reverse_port_mismatch_still_blocks() {
        let agent = json!({"user": "agent", "remote_port": 23000, "identity": "/agent"});
        let controller = json!({"user": "agent", "reverse_port": 23001, "identity": "/controller"});
        let mut report = report();
        compare_gateway_pair(&agent, &controller, &mut report);
        assert!(
            report
                .blockers
                .iter()
                .any(|s| s.contains("reverse ports differ"))
        );
    }
}
