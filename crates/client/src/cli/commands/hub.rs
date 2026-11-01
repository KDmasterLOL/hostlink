use crate::cli::args::{Command, HubCommand};
use hostlink::bootstrap::{self, Target};
use hostlink::host::Host;
use hostlink::hub::{HubClient, HubConfig};
use secrecy::ExposeSecret;
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
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
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                }
            }
            let bytes = serde_json::to_vec_pretty(&config)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    io::Error::new(
                        error.kind(),
                        "Hub config already exists; remove it explicitly before reconfiguring",
                    )
                } else {
                    error
                }
            })?;
            let publication = set_private_file_acl(&mut file)
                .and_then(|()| file.write_all(&bytes))
                .and_then(|()| file.sync_all());
            drop(file);
            if let Err(error) = publication {
                return match fs::remove_file(&path) {
                    Ok(()) => Err(error.into()),
                    Err(cleanup) => Err(io::Error::other(format!(
                        "Hub config write failed: {error}; owned partial config cleanup failed: {cleanup}"
                    )).into()),
                };
            }
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

#[cfg(windows)]
fn set_private_file_acl(file: &mut File) -> io::Result<()> {
    use windows_permissions::{
        SecurityDescriptor,
        constants::{SeObjectType, SecurityInformation},
        utilities::current_process_sid,
        wrappers::SetSecurityInfo,
    };

    let owner = current_process_sid()?;
    let descriptor: windows_permissions::LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{owner})")
            .parse()
            .map_err(|error: io::Error| error)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| io::Error::other("private config ACL could not be constructed"))?;
    SetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl | SecurityInformation::Owner,
        Some(&owner),
        None,
        Some(dacl),
        None,
    )
}

#[cfg(not(windows))]
fn set_private_file_acl(_file: &mut File) -> io::Result<()> {
    Ok(())
}

pub(super) async fn dispatch(
    command: &crate::cli::args::Command,
) -> Result<Option<i32>, Box<dyn Error>> {
    match command {
        crate::cli::args::Command::Hub { command } => Ok(Some(hub_command(command).await?)),
        command @ crate::cli::args::Command::Invite { .. } => Ok(Some(invite(command).await?)),
        crate::cli::args::Command::DisplayName { host, display_name } => {
            let (client, _) = configured_hub_client()?;
            let host = client.resolve_host(host).await?;
            let updated = client.set_display_name(&host, display_name).await?;
            serde_json::to_writer_pretty(io::stdout().lock(), &updated)?;
            io::stdout().lock().write_all(b"\n")?;
            Ok(Some(0))
        }
        crate::cli::args::Command::Remove { host, yes } => {
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
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}

async fn invite(command: &Command) -> Result<i32, Box<dyn Error>> {
    let Command::Invite {
        name,
        ssh_user,
        ttl_seconds,
        token_only,
        embed_github_token,
        version,
        target,
        bootstrap_hub_ca_cert,
    } = command
    else {
        return Err("internal invite dispatch mismatch".into());
    };
    let config_path = default_hub_config_path()?;
    let config = load_hub_config(&config_path)?;
    let selection = if *token_only {
        if name.is_some() && name.as_deref().is_some_and(|value| value.trim().is_empty()) {
            return Err("invitation name cannot be empty".into());
        }
        None
    } else {
        let get = |value: &Option<String>, flag: &str| -> Result<String, Box<dyn Error>> {
            value
                .clone()
                .ok_or_else(|| format!("{flag} is required unless --token-only is used").into())
        };
        let selected_name = name
            .clone()
            .ok_or("--name is required for a runnable bootstrap")?;
        let selected_target = Target::parse(&get(target, "--target")?)?;
        if selected_target.windows() && bootstrap_hub_ca_cert.is_some() {
            return Err(
                "--bootstrap-hub-ca-cert is supported only by the POSIX Linux installer".into(),
            );
        }
        let selection = bootstrap::resolve_github_selection(
            version.as_deref(),
            selected_target,
            selected_name,
            ssh_user.clone().unwrap_or_else(|| config.ssh_user.clone()),
            config.hub_url.clone(),
            bootstrap_hub_ca_cert.clone(),
        )
        .await?;
        Some(selection)
    };
    // Download, bound, hash, and inspect the exact installer before consuming an invite.
    let verified = match &selection {
        Some(selection) => {
            Some(bootstrap::verify_installer(selection, config.hub_ca_cert.as_deref()).await?)
        }
        None => None,
    };
    // Construct the complete command before consuming the one-use Hub invite.
    // Any credential/configuration error must not burn an invitation.
    let bootstrap_command = match (&selection, &verified) {
        (Some(selection), Some(verified)) if *embed_github_token => {
            Some(bootstrap::render_command_embedded(selection, verified)?)
        }
        (Some(selection), Some(verified)) => Some(bootstrap::render_command(selection, verified)),
        _ => None,
    };
    if selection.is_some() {
        eprintln!(
            "GitHub SHA-256 authenticates API-selected bytes; it is not an independent publisher signature."
        );
    }
    if *embed_github_token {
        eprintln!(
            "WARNING: bootstrap_command contains your GitHub PAT in plain text. +             Protect stdout, terminal history and clipboard; delete any saved +             Windows bootstrap helper after installation. Every target receiving +             this PAT can read the authorized private GitHub repository."
        );
    }
    let client = HubClient::from_config(&config)?;
    let pending = Host::create(&client, name.clone(), *ttl_seconds).await?;
    let invite = pending.into_invitation();
    println!(
        "token: {}\nexpires_at: {}",
        invite.token.expose_secret(),
        invite.expires_at
    );
    if let (Some(verified), Some(bootstrap_command)) = (&verified, bootstrap_command) {
        println!(
            "artifact_binding: verified\ninstaller_sha256: {}\nbootstrap_command:\n{}",
            verified.sha256, bootstrap_command
        );
    } else {
        println!("artifact_binding: token-only; no bootstrap command");
    }
    Ok(0)
}
