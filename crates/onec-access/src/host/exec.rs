//! Interactive operator SSH execution through the generated managed configuration.

use super::*;

pub(super) const WINDOWS_INTERACTIVE_COMMAND_MAX_BYTES: usize = 8_000;

/// Runs an operator-attached OpenSSH session through the generated managed configuration.
///
/// Unlike background/control transport, stdin/stdout/stderr remain attached to the operator
/// terminal. Remote argv is encoded explicitly for the target OS when a command is supplied.
///
/// # Errors
///
/// Returns [`crate::AppError`] when the agent cannot be projected to a managed host alias, generated SSH
/// config/tooling is missing, remote argv encoding fails, or OpenSSH cannot be started.
pub async fn run_managed_ssh(
    client: &HubClient,
    agent: &HubAgent,
    remote_command: &[String],
    tty: bool,
) -> AppResult<i32> {
    let destination = managed_ssh_destination(agent)?;
    let encoded_remote_command = if remote_command.is_empty() {
        None
    } else {
        Some(encode_remote_command(remote_command, &agent.os)?)
    };
    if let Some(encoded) = encoded_remote_command.as_deref() {
        check_interactive_command_length(encoded, &agent.os)?;
    }
    let config = managed_ssh_config_path()?;
    if !config.is_file() {
        return Err(crate::not_found_error(format!(
            "managed SSH config {}; run `onec-access sync-ssh` first",
            config.display()
        )));
    }
    let ssh = resolve_ssh_tool()?;
    let program = ssh.path;
    let identity = client.config().identity.as_deref().ok_or_else(|| {
        crate::invalid_config(
            "onec-access config needs `identity` before standard SSH can be used".to_owned(),
        )
    })?;
    // Preflight the final encoded command before any gateway probe or SSH traffic.
    let gateways = client.gateway_routes().await?;
    let gateway_index =
        crate::remote::select_managed_ssh_gateway(&gateways, identity, agent.remote_port).await?;
    let proxy_jump = gateway_alias(gateway_index);
    // Deliberately interactive: keep this attached to the operator terminal. Background/control
    // SSH paths use the shared hidden-process policy instead.
    let mut command = managed_ssh_command(&program, &config, &destination, &proxy_jump, tty)?;
    if let Some(encoded) = encoded_remote_command {
        // OpenSSH does not preserve argv boundaries for a remote command: it serializes the
        // remaining local argv into one command string which the remote login shell parses
        // again. Passing `command.args(remote_command)` therefore corrupts Windows paths with
        // spaces, 1C connection strings containing `;`, and commit messages. Encode exactly
        // one shell-safe command string here and reconstruct argv on the remote host.
        command.arg(encoded);
    }
    apply_managed_ssh_environment(&mut command);
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| {
            crate::process_start_error(program, format!("standard SSH to {destination}"), source)
        })?;
    Ok(status.code().unwrap_or(1))
}

/// Restricts the operator-attached SSH child to the runtime inputs it needs.
/// OpenSSH reads its managed configuration explicitly via `-F`; `SSH_AUTH_SOCK` is
/// retained when present so operator agent authentication continues to work.
pub(super) fn apply_managed_ssh_environment(command: &mut Command) {
    const ALLOWED: &[&str] = &[
        "PATH",
        "HOME",
        "USERPROFILE",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "TERM",
        "SSH_AUTH_SOCK",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
    ];
    let inherited = ALLOWED
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| ((*name).to_owned(), value)))
        .collect::<Vec<_>>();
    command.env_clear();
    command.envs(inherited);
}

pub(super) fn check_interactive_command_length(encoded: &str, remote_os: &str) -> AppResult<()> {
    let os = remote_os.trim().to_ascii_lowercase();
    if !(os.contains("windows") || os.starts_with("win")) {
        return Ok(());
    }

    let encoded_bytes = encoded.len();
    if encoded_bytes > WINDOWS_INTERACTIVE_COMMAND_MAX_BYTES {
        return Err(crate::invalid_config(format!(
            "encoded Windows interactive SSH command is {encoded_bytes} bytes; the conservative limit is {WINDOWS_INTERACTIVE_COMMAND_MAX_BYTES} bytes. Use `onec-access upload` for a file or script, or `onec-access exec --stdin-file` only with a verified stdin-consuming program."
        )));
    }
    Ok(())
}

pub(super) fn managed_ssh_command(
    program: &Path,
    config: &Path,
    destination: &str,
    proxy_jump: &str,
    tty: bool,
) -> AppResult<Command> {
    let mut command = Command::new(program);
    command.arg("-F").arg(ssh_argv_path(config)?);
    if tty {
        command.arg("-t");
    }
    command.arg("-o").arg(format!("ProxyJump={proxy_jump}"));
    command.arg(destination);
    Ok(command)
}

pub(super) fn managed_ssh_destination(agent: &HubAgent) -> AppResult<String> {
    ssh_alias(&agent.name)
}

/// Resolves one managed SSH agent by exact name first, then exact hostname.
///
/// # Errors
///
/// Returns [`crate::AppError`] for an empty selector, ambiguous name/hostname, or no matching host.
pub fn resolve_managed_ssh_agent(agents: &[HubAgent], requested: &str) -> AppResult<HubAgent> {
    let requested = requested.trim();
    if requested.is_empty() {
        return Err(crate::invalid_config(
            "managed SSH host selector must not be empty".to_owned(),
        ));
    }

    let by_name = agents
        .iter()
        .filter(|agent| agent.name.eq_ignore_ascii_case(requested))
        .cloned()
        .collect::<Vec<_>>();
    match by_name.as_slice() {
        [agent] => return Ok(agent.clone()),
        [] => {}
        _ => {
            return Err(crate::invalid_config(format!(
                "managed SSH host name {requested:?} is ambiguous"
            )));
        }
    }

    let by_hostname = agents
        .iter()
        .filter(|agent| agent.hostname.eq_ignore_ascii_case(requested))
        .cloned()
        .collect::<Vec<_>>();
    match by_hostname.as_slice() {
        [agent] => Ok(agent.clone()),
        [] => Err(crate::not_found_error(format!(
            "hub-managed host {requested:?}"
        ))),
        _ => Err(crate::invalid_config(format!(
            "managed SSH machine hostname {requested:?} is ambiguous"
        ))),
    }
}
