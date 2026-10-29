use super::*;

pub(super) fn parse_hub_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid("Hub URL must be an HTTPS origin"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "")
    {
        return Err(invalid(
            "Hub URL must be an HTTPS origin without credentials, path, query or fragment",
        ));
    }
    Ok(url)
}

pub(super) fn validate_response(
    response: &EnrollResponse,
    machine_id: &MachineId,
    name: &str,
    reverse_public: &str,
    host_public: &str,
    gateway_index: Option<usize>,
) -> io::Result<Vec<GatewayEndpoint>> {
    if &response.host.machine_id != machine_id
        || response.host.name != name
        || response.host.remote_port == 0
        || response.host.ssh_public_key != reverse_public
        || response.host.ssh_host_public_key != host_public
    {
        return Err(invalid(
            "Hub enrollment response does not match the submitted identity and keys",
        ));
    }
    if response.operator_ssh_public_keys.is_empty() || response.operator_ssh_public_keys.len() > 32
    {
        return Err(invalid(
            "Hub returned no authorized Controller keys or too many keys",
        ));
    }
    let mut seen_keys = std::collections::BTreeSet::new();
    for key in &response.operator_ssh_public_keys {
        let canonical = hostlink_hub::canonical_ed25519_public_key(key).map_err(invalid_data)?;
        if !seen_keys.insert(canonical) {
            return Err(invalid("Hub returned duplicate authorized Controller keys"));
        }
    }
    if response.gateways.is_empty() || response.gateways.len() > 16 {
        return Err(invalid(
            "Hub returned no approved gateway routes or too many routes",
        ));
    }
    let mut seen_routes = std::collections::BTreeSet::new();
    for endpoint in &response.gateways {
        endpoint.validate().map_err(invalid_data)?;
        let pin = hostlink_hub::canonical_ed25519_public_key(&endpoint.host_public_key)
            .map_err(invalid_data)?;
        if !seen_routes.insert((
            endpoint.host.to_ascii_lowercase(),
            endpoint.user.clone(),
            endpoint.port,
            pin,
        )) {
            return Err(invalid("Hub returned duplicate gateway routes"));
        }
    }
    let selected_index = match (response.gateways.as_slice(), gateway_index) {
        ([_], None) => 0,
        (routes, Some(index)) if index < routes.len() => index,
        (_, None) => {
            return Err(invalid(
                "Hub approved multiple gateways; rerun with an explicit --gateway-index",
            ));
        }
        (_, Some(_)) => return Err(invalid("selected gateway index is not in Hub response")),
    };
    let mut selected = Vec::with_capacity(response.gateways.len());
    selected.push(response.gateways[selected_index].clone());
    selected.extend(
        response
            .gateways
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != selected_index)
            .map(|(_, endpoint)| endpoint.clone()),
    );
    Ok(selected)
}

pub(super) fn validate_inputs(options: &EnrollmentOptions) -> io::Result<()> {
    parse_hub_url(&options.hub_url)?;
    if !canonical_name(&options.name) {
        return Err(invalid("Agent name must be canonical lowercase ASCII"));
    }
    if options.user.is_empty()
        || options.user.len() > 128
        || options.user.chars().any(char::is_whitespace)
    {
        return Err(invalid("Agent SSH user is invalid"));
    }
    if !options.install_root.is_absolute() {
        return Err(invalid("Agent install root must be absolute"));
    }
    Ok(())
}

pub(super) fn canonical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
