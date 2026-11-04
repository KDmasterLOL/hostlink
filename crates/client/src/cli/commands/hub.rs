use crate::cli::args::{HubCommand, InviteArgs};
use crate::cli::invite as invite_source;
use hostlink::host::Host;
use hostlink::hub::{HubClient, HubConfig, select_primary_gateway};
use private_fs::{Durability, PrivateDir, Publication};
use secrecy::ExposeSecret;
use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::PathBuf,
};

pub(super) fn default_hub_config_path() -> Result<PathBuf, Box<dyn Error>> {
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA").ok_or("APPDATA is unavailable")?;
    #[cfg(not(windows))]
    let root = std::env::var_os("HOME").ok_or("HOME is unavailable")?;
    #[cfg(windows)]
    let path = PathBuf::from(root).join("HostLink").join("hub.json");
    #[cfg(not(windows))]
    let path = PathBuf::from(root).join(".config/hostlink/hub.json");
    Ok(std::env::var_os("HOSTLINK_HUB_CONFIG")
        .map(PathBuf::from)
        .unwrap_or(path))
}

pub(super) fn load_hub_config(path: &std::path::Path) -> Result<HubConfig, Box<dyn Error>> {
    Ok(HubClient::read_config(path)?)
}

pub(super) fn configured_hub_client() -> Result<(HubClient, HubConfig), Box<dyn Error>> {
    Ok(HubClient::from_file(&default_hub_config_path()?)?)
}

pub(super) async fn hub_command(command: &HubCommand) -> Result<i32, Box<dyn Error>> {
    match command {
        HubCommand::Configure {
            hub_url,
            hub_ca_cert,
            token_file,
            ssh_user,
            identity,
            gateway_identity,
            preferred_gateway,
        } => {
            let config = HubConfig {
                hub_url: hub_url.clone(),
                hub_ca_cert: hub_ca_cert.clone(),
                token_file: token_file.clone(),
                ssh_user: ssh_user.clone(),
                identity: identity.clone(),
                gateway_identity: gateway_identity.clone(),
                preferred_gateway: preferred_gateway.clone(),
            };
            HubClient::from_config(&config)?;
            let path = default_hub_config_path()?;
            let parent = path.parent().ok_or("Hub config directory is unavailable")?;
            let file_name = path
                .file_name()
                .ok_or("Hub config filename is unavailable")?;
            // Public container directories (such as ~/.config) may be shared.
            // Only the HostLink-owned leaf is private; existing roots are never
            // chmod'ed or adopted when their permissions do not meet policy.
            if let Some(container) = parent.parent() {
                fs::create_dir_all(container)?;
            }
            let private_dir = PrivateDir::ensure(parent)?;
            let bytes = serde_json::to_vec_pretty(&config)?;
            let mut writer = private_dir.atomic_with_policy(
                file_name,
                Durability::Full,
                Publication::CreateNew,
            )?;
            writer.write_all(&bytes)?;
            // A failed commit may have published; never remove an ambiguous
            // destination or overwrite a previously created configuration.
            writer.commit()?;
            println!("Hub config saved to {}", path.display());
        }
        HubCommand::Show => {
            let config = load_hub_config(&default_hub_config_path()?)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &config)?;
            io::stdout().lock().write_all(b"\n")?;
        }
        HubCommand::Check => {
            let (client, _) = configured_hub_client()?;
            let gateways = client.info().await?;
            println!(
                "Hub v2 management API reachable; approved gateways: {}",
                gateways.len()
            );
        }
    }
    Ok(0)
}

pub(super) async fn display_name(host: &str, display_name: &str) -> Result<i32, Box<dyn Error>> {
    let (client, _) = configured_hub_client()?;
    let host = client.resolve_host(host).await?;
    let updated = client.set_display_name(&host, display_name).await?;
    serde_json::to_writer_pretty(io::stdout().lock(), &updated)?;
    io::stdout().lock().write_all(b"\n")?;
    Ok(0)
}

pub(super) async fn remove(host: &str, yes: bool) -> Result<i32, Box<dyn Error>> {
    if !yes {
        return Err("revocation requires explicit --yes confirmation".into());
    }
    let (client, _) = configured_hub_client()?;
    let host = client.resolve_host(host).await?;
    let receipt = client.revoke(&host).await?;
    println!(
        "revoked {}: new_connections={}, existing_sessions_terminated={}, remote_uninstall={}, projection={}",
        host.machine_id,
        receipt.revoked_new_connections,
        receipt.confirmed_session_terminated,
        receipt.remote_uninstall,
        receipt.authorized_key_projection
    );
    Ok(0)
}

pub(super) async fn invite(args: InviteArgs) -> Result<i32, Box<dyn Error>> {
    let InviteArgs {
        name,
        legacy_name,
        ssh_user,
        ttl_seconds,
        token_only,
        version,
        target,
        os,
        bootstrap_hub_ca_cert,
        gateway_index,
    } = args;
    let name = name.or(legacy_name);
    let config_path = default_hub_config_path()?;
    let config = load_hub_config(&config_path)?;
    // Resolve against the authenticated, pin-validated inventory before minting a one-use invite.
    let client = HubClient::from_config(&config)?;
    let gateways = client.info().await?;
    let gateway_index = match gateway_index {
        Some(index) if index < gateways.len() => index,
        Some(_) => return Err("--gateway-index is outside the Hub-approved gateway list; check hostlink hub check and /v2/info".into()),
        None => select_primary_gateway(&gateways, config.preferred_gateway.as_deref())?,
    };
    let selection = if token_only {
        if name.is_some() && name.as_deref().is_some_and(|value| value.trim().is_empty()) {
            return Err("invitation name cannot be empty".into());
        }
        None
    } else {
        let selected_name = name
            .clone()
            .ok_or("--name is required for a runnable bootstrap")?;
        let selected_user = ssh_user.unwrap_or_else(|| config.ssh_user.clone());
        let selections = if let Some(os) = os {
            let family = if os == "windows" {
                invite_source::OsFamily::Windows
            } else {
                invite_source::OsFamily::Linux
            };
            invite_source::resolve_github_family(
                version.as_deref(),
                family,
                selected_name,
                selected_user,
                config.hub_url.clone(),
                bootstrap_hub_ca_cert,
                Some(gateway_index),
            )
            .await?
        } else {
            vec![
                invite_source::resolve_github_selection(
                    version.as_deref(),
                    target.ok_or("--os or --target is required")?,
                    selected_name,
                    selected_user,
                    config.hub_url.clone(),
                    bootstrap_hub_ca_cert,
                    Some(gateway_index),
                )
                .await?,
            ]
        };
        Some(selections)
    };
    // Resolve the exact raw asset/digest and render before creating a Hub invite.
    // Target-side SHA-256 verification precedes the invite token prompt and install.
    let bootstrap_command = match &selection {
        Some(selection) => Some(invite_source::prepare_inline(selection)?),
        None => None,
    };
    if selection.is_some() {
        eprintln!(
            "GitHub metadata supplies the SHA-256 pin; it is not an independent publisher signature."
        );
    }
    if selection.is_some() {
        eprintln!(
            "WARNING: the command contains a one-use invitation; protect terminal history and clipboard."
        );
    }
    let pending = Host::create(&client, name, ttl_seconds).await?;
    let invite = pending.into_invitation();
    if let Some(bootstrap_command) = bootstrap_command {
        println!("{}", bootstrap_command.bind(invite.token.expose_secret())?);
    } else {
        println!(
            "token: {}\nexpires_at: {}\nartifact_binding: token-only; no bootstrap command",
            invite.token.expose_secret(),
            invite.expires_at
        );
    }
    Ok(0)
}
