use super::*;

pub(crate) struct HubConfigureArgs {
    pub(crate) url: String,
    pub(crate) gateway: String,
    pub(crate) gateway_user: String,
    pub(crate) gateway_port: u16,
    pub(crate) identity: Option<std::path::PathBuf>,
    pub(crate) known_hosts: Option<std::path::PathBuf>,
    pub(crate) release_base_url: Option<String>,
    pub(crate) token_env: Option<String>,
    pub(crate) token_file: Option<std::path::PathBuf>,
}

pub(super) fn configure(args: HubConfigureArgs) -> AppResult<()> {
    let mut config = HubControllerConfig::new(args.url, args.gateway, args.gateway_user)?;
    config.gateways[0].port = args.gateway_port;
    config.identity = args.identity;
    config.known_hosts = args.known_hosts;
    config.release_base_url = args
        .release_base_url
        .as_deref()
        .map(HubHttpsUrl::parse)
        .transpose()?;
    config.token_file = args.token_file;
    config.token_env = if config.token_file.is_some() {
        String::new()
    } else {
        args.token_env
            .unwrap_or_else(|| "ONEC_HUB_OPERATOR_TOKEN".to_owned())
    };
    config.save()?;
    println!(
        "onec-access controller configured: {}",
        hub_config_path()?.display()
    );
    Ok(())
}

pub(super) async fn check() -> AppResult<()> {
    let config_path = hub_config_path()?;
    let client = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "onec-access controller config {}",
            config_path.display()
        ))
    })?;
    let agents = client.list_agents().await?;
    println!(
        "onec-hub is reachable through onec-access; enrolled hosts: {}",
        agents.len()
    );
    Ok(())
}

pub(super) fn show() -> AppResult<()> {
    let config = HubControllerConfig::load()?;
    crate::cli::output::print_pretty_json(&config);
    Ok(())
}
