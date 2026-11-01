//! Disposable, target-local bootstraps: credentials, one raw binary, then Rust install.

use super::validate::ArtifactSelection;

pub fn render_command(selection: &ArtifactSelection) -> String {
    render_command_with_token(selection, None)
}

/// Only the explicit CLI opt-in may supply a Controller PAT here.
pub(super) fn render_command_with_token(
    selection: &ArtifactSelection,
    token: Option<&str>,
) -> String {
    if selection.target.windows() {
        render_powershell(selection, token)
    } else {
        render_posix(selection, token)
    }
}

fn render_powershell(selection: &ArtifactSelection, token: Option<&str>) -> String {
    let ca = selection
        .bootstrap_hub_ca_cert
        .as_deref()
        .map(|path| path.to_string_lossy())
        .unwrap_or_default();
    let vars = [
        ("HubUrl", selection.hub_url.as_str()),
        ("Name", selection.name.as_str()),
        ("SshUser", selection.ssh_user.as_str()),
        ("AgentUri", selection.agent_url.as_str()),
        ("AgentSha256", selection.agent_sha256.as_str()),
        ("Target", selection.target.as_str()),
        ("HubCaCert", ca.as_ref()),
    ]
    .into_iter()
    .map(|(name, value)| format!("${name}={}\n", ps_quote(value)))
    .collect::<String>();
    let helpers = include_str!("../../assets/github-windows.ps1");
    let body = include_str!("../../assets/bootstrap-windows.ps1");
    let provision = token.map_or_else(
        || "[void](Get-GitHubCredential $true)".to_owned(),
        |token| format!("[void](Get-GitHubCredential $true {})", ps_quote(token)),
    );
    let script = format!(
        "param([switch]$NoRun)\n$ErrorActionPreference='Stop'\nSet-PSDebug -Off\n{helpers}\n{vars}\n{provision}\n{body}"
    );
    let utf16le = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let command = format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, utf16le)
    );
    if command.len() <= 8191 {
        command
    } else {
        let note = if token.is_some() {
            "WARNING: This helper contains your GitHub PAT in plain text. Save it privately, never share it, and delete it after installation."
        } else {
            "No GitHub credential is included. Delete the helper after installation."
        };
        format!(
            "1. On the TARGET save the script between the markers privately as %TEMP%\\hostlink-bootstrap.ps1 (UTF-8 with BOM). {note}\n2. In an unelevated target cmd.exe run (optionally append -NoRun):\npowershell -NoProfile -ExecutionPolicy Bypass -File \"%TEMP%\\hostlink-bootstrap.ps1\"\n# BEGIN TARGET HELPER\n{script}# END TARGET HELPER\n"
        )
    }
}

fn render_posix(selection: &ArtifactSelection, token: Option<&str>) -> String {
    let ca = selection
        .bootstrap_hub_ca_cert
        .as_deref()
        .map(|path| path.to_string_lossy())
        .unwrap_or_default();
    let vars = [
        ("hub_url", selection.hub_url.as_str()),
        ("name", selection.name.as_str()),
        ("ssh_user", selection.ssh_user.as_str()),
        ("agent_url", selection.agent_url.as_str()),
        ("agent_sha256", selection.agent_sha256.as_str()),
        ("hub_ca_cert", ca.as_ref()),
    ]
    .into_iter()
    .map(|(name, value)| format!("{name}={}\n", sh_quote(value)))
    .collect::<String>();
    let helpers = include_str!("../../assets/github-posix.sh");
    let body = include_str!("../../assets/bootstrap-posix.sh");
    let provision = token.map_or_else(
        || "hl_provision_credential".to_owned(),
        |token| format!("hl_provision_credential {}", sh_quote(token)),
    );
    format!("(\nset -eu\n{helpers}\n{vars}\n{provision}\n{body})\n")
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
