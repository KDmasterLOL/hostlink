//! Hub inventory projection into deterministic, independently pinned SSH routes.

use std::{net::SocketAddr, time::Duration};

use hostlink_hub::{GatewayEndpoint, RegisteredHost};

use crate::{GatewayHop, GatewayRoute, HostSpec};

use super::config::{HubClientError, HubConfig};

pub(super) fn validate_pin(value: &str) -> Result<(), HubClientError> {
    let key: russh::keys::PublicKey = value
        .parse()
        .map_err(|_| HubClientError::Invalid("Hub supplied an invalid SSH host key".into()))?;
    if key.algorithm().to_string() != "ssh-ed25519" {
        return Err(HubClientError::Invalid(
            "Hub SSH host key must be Ed25519".into(),
        ));
    }
    Ok(())
}

/// Resolves the host's exact gateway pins from one authoritative Hub inventory.
///
/// Only a trusted configured gateway is a valid primary when the Hub advertises
/// multiple routes. The remaining Hub-approved routes are retained solely for
/// transient initial-connection failures, never for key/authentication failures.
pub async fn host_spec_from_approved_routes(
    host: RegisteredHost,
    gateways: &[GatewayEndpoint],
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    validate_gateway_list(gateways)?;
    let primary_index = match (gateways, config.preferred_gateway.as_deref()) {
        ([_], None) => 0,
        ([], _) => {
            return Err(HubClientError::Invalid(
                "Hub has no approved gateway".into(),
            ));
        }
        (_, selected) => select_primary_gateway(gateways, selected)?,
    };
    // A healthy explicitly selected gateway must not become unusable merely
    // because an optional Hub-approved alternate is temporarily missing in DNS.
    // Resolve alternates concurrently so many offline edges do not multiply
    // the controller's discovery deadline. All pins were validated above.
    let mut addresses = vec![None; gateways.len()];
    addresses[primary_index] = Some(resolve_gateway(&gateways[primary_index]).await?);
    let mut optional = tokio::task::JoinSet::new();
    for (index, gateway) in gateways.iter().enumerate() {
        if index != primary_index {
            let gateway = gateway.clone();
            optional.spawn(async move { (index, resolve_gateway(&gateway).await) });
        }
    }
    while let Some(result) = optional.join_next().await {
        let (index, address) = result.map_err(|_| HubClientError::GatewayDns)?;
        if let Ok(address) = address {
            addresses[index] = Some(address);
        }
    }

    let primary_address = addresses[primary_index].expect("selected primary was resolved");
    let mut routes = Vec::with_capacity(gateways.len());
    routes.push((&gateways[primary_index], primary_address));
    let mut resolved = std::collections::BTreeSet::new();
    resolved.insert((primary_address, gateways[primary_index].user.as_str()));
    for (index, (gateway, address)) in gateways.iter().zip(addresses).enumerate() {
        if index == primary_index {
            continue;
        }
        if let Some(address) = address {
            if !resolved.insert((address, gateway.user.as_str())) {
                return Err(HubClientError::Invalid(
                    "Hub routes resolve to duplicate gateway endpoints".into(),
                ));
            }
            routes.push((gateway, address));
        }
    }
    host_spec_from_routes(host, &routes, config)
}

fn host_spec_from_routes(
    host: RegisteredHost,
    routes: &[(&GatewayEndpoint, SocketAddr)],
    config: &HubConfig,
) -> Result<HostSpec, HubClientError> {
    let (gateway, address) = routes.first().ok_or(HubClientError::Response)?;
    validate_pin(&host.ssh_host_public_key)?;
    let mut alternates = Vec::with_capacity(routes.len().saturating_sub(1));
    for (endpoint, address) in routes.iter().skip(1) {
        validate_pin(&endpoint.host_public_key)?;
        alternates.push(GatewayRoute {
            address: *address,
            user: endpoint.user.clone(),
            identity: config.gateway_identity.clone(),
            host_public_key: endpoint.host_public_key.clone(),
        });
    }
    Ok(HostSpec {
        endpoint: SocketAddr::from(([127, 0, 0, 1], host.remote_port)),
        user: config.ssh_user.clone(),
        identity: config.identity.clone(),
        host_public_key: host.ssh_host_public_key,
        gateway: Some(GatewayHop {
            address: *address,
            user: gateway.user.clone(),
            identity: config.gateway_identity.clone(),
            host_public_key: gateway.host_public_key.clone(),
            reverse_port: host.remote_port,
            alternates,
        }),
    })
}

pub(super) fn validate_gateway_list(gateways: &[GatewayEndpoint]) -> Result<(), HubClientError> {
    if gateways.len() > 16 {
        return Err(HubClientError::Invalid(
            "Hub lists more than 16 approved gateways".into(),
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut pins = std::collections::BTreeSet::new();
    for gateway in gateways {
        gateway.validate().map_err(HubClientError::Invalid)?;
        if gateway.user.is_empty()
            || gateway.user.len() > 64
            || !gateway
                .user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(HubClientError::Invalid(
                "Hub gateway SSH user is invalid for the Client".into(),
            ));
        }
        let identity = (
            gateway.host.to_ascii_lowercase(),
            gateway.port,
            gateway.user.as_str(),
        );
        if !identities.insert(identity) {
            return Err(HubClientError::Invalid(
                "Hub lists a duplicate gateway identity".into(),
            ));
        }
        if !pins.insert(gateway.host_public_key.as_str()) {
            return Err(HubClientError::Invalid(
                "Hub lists a duplicate gateway host key pin".into(),
            ));
        }
        validate_pin(&gateway.host_public_key)?;
    }
    Ok(())
}

pub(super) fn select_primary_gateway(
    gateways: &[GatewayEndpoint],
    preferred: Option<&str>,
) -> Result<usize, HubClientError> {
    let Some(preferred) = preferred else {
        return Err(HubClientError::Invalid(
            "Hub lists multiple gateways; set preferred_gateway to an exact host:port from /v2/info".into(),
        ));
    };
    let matches: Vec<_> = gateways
        .iter()
        .enumerate()
        .filter(|(_, gateway)| format!("{}:{}", gateway.host, gateway.port) == preferred)
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(HubClientError::Invalid(
            "preferred_gateway does not match exactly one Hub-approved host:port".into(),
        )),
    }
}

pub(super) async fn resolve_gateway(
    gateway: &GatewayEndpoint,
) -> Result<SocketAddr, HubClientError> {
    let mut addresses = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((gateway.host.as_str(), gateway.port)),
    )
    .await
    .map_err(|_| HubClientError::GatewayDns)?
    .map_err(|_| HubClientError::GatewayDns)?;
    let first = addresses.next().ok_or(HubClientError::GatewayDns)?;
    if addresses.next().is_some() {
        return Err(HubClientError::GatewayDns);
    }
    Ok(first)
}
