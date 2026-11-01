use serde_json::Value;

use super::{
    HostReadiness,
    paths::{string_field, valid_host_pin},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Route {
    pub(super) host: String,
    pub(super) user: String,
    pub(super) port: u64,
}

pub(super) fn old_hub_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
    // An empty Hub list with explicit single-route fields is a supported legacy schema.
    let routes = if let Some(items) = value
        .get("gateways")
        .filter(|items| !items.as_array().is_some_and(Vec::is_empty))
    {
        route_collection(
            items,
            report,
            "legacy Hub gateway collection is empty or malformed",
        )
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
        .any(|route| route.user.is_empty() || !(1..=65535).contains(&route.port))
    {
        block(report, "legacy Hub gateway route is incomplete");
    }
    routes
}

pub(super) fn inspect_old_hub_pins(value: &Value, report: &mut HostReadiness) {
    let pins: Vec<Option<String>> = if let Some(collection) = value
        .get("gateways")
        .filter(|items| !items.as_array().is_some_and(Vec::is_empty))
    {
        let Some(gateways) = collection.as_array() else {
            block(
                report,
                "legacy Hub gateway collection is empty or malformed",
            );
            return;
        };
        if gateways
            .iter()
            .any(|gateway| route_object(gateway).is_none())
        {
            block(
                report,
                "legacy Hub gateway collection is empty or malformed",
            );
        }
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

pub(super) fn old_controller_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
    let routes = if let Some(items) = value.get("gateways") {
        route_collection(
            items,
            report,
            "legacy Controller gateway collection is empty or malformed",
        )
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
        .any(|route| route.user.is_empty() || !(1..=65535).contains(&route.port))
    {
        block(report, "legacy Controller gateway route is incomplete");
    }
    routes
}

pub(super) fn old_agent_gateways(value: &Value, report: &mut HostReadiness) -> Vec<Route> {
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
    let routes = if let Some(items) = ssh.get("gateways") {
        route_collection(
            items,
            report,
            "legacy Agent gateway collection is empty or malformed",
        )
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
    };
    if routes
        .iter()
        .any(|route| route.user.is_empty() || !(1..=65535).contains(&route.port))
    {
        block(report, "legacy Agent gateway route is incomplete");
    }
    routes
}

fn route_collection(value: &Value, report: &mut HostReadiness, reason: &str) -> Vec<Route> {
    // Collect all records or reject the collection; never drop an invalid member.
    match value
        .as_array()
        .filter(|items| !items.is_empty())
        .and_then(|items| items.iter().map(route_object).collect::<Option<Vec<_>>>())
    {
        Some(routes) => routes,
        None => {
            block(report, reason);
            Vec::new()
        }
    }
}

fn route_object(value: &Value) -> Option<Route> {
    Some(Route {
        host: string_field(value, "host")?,
        user: string_field(value, "user")?,
        port: value
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65535).contains(port))?,
    })
}

pub(super) fn has_tls_proxy(value: &Value) -> bool {
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
pub(super) fn block(report: &mut HostReadiness, reason: &str) {
    report.blockers.push(reason.to_owned());
}
