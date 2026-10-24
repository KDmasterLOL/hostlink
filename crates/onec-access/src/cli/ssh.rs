use super::*;

fn configured_client() -> AppResult<HubClient> {
    let config_path = hub_config_path()?;
    HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "onec-access controller config {}; configure access first",
            config_path.display()
        ))
    })
}

pub(super) async fn sync(no_install_include: bool, json_output: bool) -> AppResult<()> {
    let report = sync_hub_ssh_hosts(&configured_client()?, !no_install_include).await?;
    if json_output {
        crate::cli::output::print_pretty_json(&report);
    } else {
        println!("SSH config: {}", report.ssh_config.display());
        println!(
            "Target known_hosts: {}",
            report.target_known_hosts.display()
        );
        if let Some(path) = report.user_ssh_config.as_deref() {
            println!("Managed Include: {}", path.display());
        }
        if report.configured_hosts.is_empty() {
            println!("No SSH-ready managed hosts");
        } else {
            println!("SSH-ready: {}", report.configured_hosts.join(", "));
        }
        for skipped in report.skipped_hosts {
            println!("Skipped {}: {}", skipped.name, skipped.reason);
        }
    }
    Ok(())
}

pub(super) async fn run(name: String, tty: bool, command: Vec<String>) -> AppResult<()> {
    let client = configured_client()?;
    let agents = client.list_agents().await?;
    let agent = resolve_managed_ssh_agent(&agents, &name)?;
    sync_hub_ssh_hosts(&client, false).await?;
    let ssh_program = resolve_ssh_tool()?.path;
    let canonical_name = agent.name.clone();
    let code = run_managed_ssh(&client, &agent, &command, tty).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(crate::process_failed_error(
            ssh_program,
            format!("standard SSH command on {canonical_name}"),
            Some(code),
            "OpenSSH returned a non-zero exit status".to_owned(),
        ))
    }
}
