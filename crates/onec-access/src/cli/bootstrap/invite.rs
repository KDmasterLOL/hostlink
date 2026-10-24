use super::super::*;
use super::direct::{DirectInstall, validate_direct_install};
use super::render::{
    RemoteDirectInviteBootstrap, powershell_command_line, ps_single_quote,
    remote_direct_invite_bootstrap,
};

pub(in crate::cli) async fn invite(args: crate::cli::commands::invite::Args) -> AppResult<()> {
    if args.persistence == crate::cli::values::Persistence::WindowsService
        && !args.embedded_ssh_candidate
    {
        eprintln!(
            "warning: windows-service persistence runs onec-agent, structured exec/jobs, and target-side sshd under Windows LocalSystem"
        );
    }
    let config_path = hub_config_path()?;
    let client = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink controller config {}; run `hostlink configure ...`",
            config_path.display()
        ))
    })?;
    let public_url = client.public_url().await?;

    // Validate exact artifacts before minting the one-use enrollment token.
    let direct = direct_install(&args).await?;
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
        hub_url: &ps_single_quote(&invite.public_url.to_string()),
        package_url: direct.package_url.as_url().as_str(),
        package_sha256: &direct.package_sha256,
        package_version: &direct.package_version,
        package_target: &direct.package_target,
        persistence: args.persistence.installer_value(),
        embedded_ssh_candidate: args.embedded_ssh_candidate,
    });
    if args.embedded_ssh_candidate {
        if args.persistence == crate::cli::values::Persistence::WindowsService {
            eprintln!(
                "warning: windows-service persistence runs onec-agent, structured exec/jobs, and embedded SSH candidate under Windows LocalSystem"
            );
        }
        eprintln!(
            "warning: --embedded-ssh-candidate is an explicit canary path; running the rendered bootstrap re-enrolls that machine and is not the default fleet transport"
        );
    }
    println!(
        "Enrollment token is valid until Unix timestamp {} and can be used once.",
        invite.expires_at
    );
    println!("Enrollment token: {}", invite.token());
    println!(
        "\nRun this in a normal PowerShell session under the user that should own onec-agent:\n"
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
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::cli::Cli;
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn invite_requires_all_direct_artifact_pins_and_rejects_retired_release_flags() {
        let missing = Cli::try_parse_from(["hostlink", "invite"])
            .expect_err("invite must require direct artifact pins");
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        let retired = Cli::try_parse_from([
            "hostlink",
            "invite",
            "--release-id",
            "old",
            "--release-manifest-sha256",
            "old",
        ])
        .expect_err("retired managed-release flags must not be accepted");
        assert_eq!(retired.kind(), ErrorKind::UnknownArgument);
    }
}
