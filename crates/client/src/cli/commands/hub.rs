use crate::cli::args::{HubCommand, InviteArgs};
use hostlink::bootstrap;
use hostlink::host::Host;
use hostlink::hub::{HubClient, HubConfig};
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
        ssh_user,
        ttl_seconds,
        token_only,
        embed_github_token,
        version,
        target,
        bootstrap_hub_ca_cert,
    } = args;
    let config_path = default_hub_config_path()?;
    let config = load_hub_config(&config_path)?;
    let selection = if token_only {
        if name.is_some() && name.as_deref().is_some_and(|value| value.trim().is_empty()) {
            return Err("invitation name cannot be empty".into());
        }
        None
    } else {
        let selected_name = name
            .clone()
            .ok_or("--name is required for a runnable bootstrap")?;
        let selected_target = target.ok_or("--target is required unless --token-only is used")?;
        let selection = bootstrap::resolve_github_selection(
            version.as_deref(),
            selected_target,
            selected_name,
            ssh_user.unwrap_or_else(|| config.ssh_user.clone()),
            config.hub_url.clone(),
            bootstrap_hub_ca_cert,
        )
        .await?;
        Some(selection)
    };
    // Resolve the exact raw asset/digest and render before creating a Hub invite.
    // Target-side SHA-256 verification precedes the invite token prompt and install.
    let bootstrap_command = match &selection {
        Some(selection) if embed_github_token => {
            Some(bootstrap::render_command_embedded(selection)?)
        }
        Some(selection) => Some(bootstrap::render_command(selection)),
        None => None,
    };
    if selection.is_some() {
        eprintln!(
            "GitHub SHA-256 authenticates API-selected bytes; it is not an independent publisher signature."
        );
    }
    if embed_github_token {
        eprintln!(
            "WARNING: bootstrap_command contains your GitHub PAT in plain text. Protect stdout, terminal history and clipboard; delete any saved Windows bootstrap helper after installation. Every target receiving this PAT can read the authorized private GitHub repository."
        );
    }
    let client = HubClient::from_config(&config)?;
    let pending = Host::create(&client, name, ttl_seconds).await?;
    let invite = pending.into_invitation();
    println!(
        "token: {}\nexpires_at: {}",
        invite.token.expose_secret(),
        invite.expires_at
    );
    if let (Some(selection), Some(bootstrap_command)) = (&selection, bootstrap_command) {
        println!(
            "artifact_binding: target-verifies-before-enrollment\nagent_sha256: {}\nbootstrap_command:\n{}",
            selection.agent_sha256(),
            bootstrap_command
        );
    } else {
        println!("artifact_binding: token-only; no bootstrap command");
    }
    Ok(0)
}
