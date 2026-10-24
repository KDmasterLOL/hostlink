use super::super::*;
use super::direct::{DirectInstall, validate_direct_install};
use super::render::{
    RemoteDirectInviteBootstrap, powershell_command_line, remote_direct_invite_bootstrap,
};

pub(in crate::cli) async fn invite(args: crate::cli::commands::invite::Args) -> AppResult<()> {
    // Reject invalid target/sidecar bindings and preflight every artifact before any Hub request.
    let direct = direct_install(&args).await?;
    let config_path = hub_config_path()?;
    let client = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink controller config {}; run `hostlink configure ...`",
            config_path.display()
        ))
    })?;
    let public_url = client.public_url().await?;

    let invite = client
        .create_invite(args.name.as_deref(), args.ttl_seconds)
        .await?;
    if invite.public_url != public_url {
        return Err(crate::invalid_config(format!(
            "HostLink Hub public URL changed while creating invite: preflight={public_url:?}, invite={:?}",
            invite.public_url
        )));
    }
    let bootstrap = remote_direct_invite_bootstrap(&RemoteDirectInviteBootstrap {
        installer_url: direct.installer_url.as_url().as_str(),
        installer_sha256: &direct.installer_sha256,
        hub_url: &invite.public_url.to_string(),
        package_url: direct.package_url.as_url().as_str(),
        package_sha256: &direct.package_sha256,
        package_version: &direct.package_version,
        package_target: &direct.package_target,
        agent_executable_url: direct
            .agent_executable_url
            .as_ref()
            .map(|url| url.as_url().as_str()),
        agent_executable_sha256: direct.agent_executable_sha256.as_deref(),
    });
    println!(
        "Enrollment token is valid until Unix timestamp {} and can be used once.",
        invite.expires_at
    );
    println!("Enrollment token: {}", invite.token());
    println!(
        "\nRun this in a normal, non-elevated PowerShell session for the new HostLink Agent:\n"
    );
    println!("{}", powershell_command_line(&bootstrap));
    Ok(())
}

async fn direct_install(args: &crate::cli::commands::invite::Args) -> AppResult<DirectInstall> {
    validate_direct_install(
        &args.direct_installer_url,
        &args.direct_installer_sha256,
        &args.direct_package_url,
        &args.direct_package_sha256,
        &args.direct_package_version,
        &args.direct_package_target,
        (
            args.direct_agent_executable_url.as_deref(),
            args.direct_agent_executable_sha256.as_deref(),
        ),
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::cli::Cli;
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn invite_requires_all_direct_hostlink_artifact_pins_and_rejects_retired_flags() {
        let missing = Cli::try_parse_from(["hostlink", "invite"])
            .expect_err("invite must require direct HostLink artifact pins");
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);

        for retired in ["--embedded-ssh-candidate", "--persistence", "--release-id"] {
            let error = Cli::try_parse_from(["hostlink", "invite", retired, "windows-service"])
                .expect_err("retired or unsupported invite options must be rejected");
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }
}
