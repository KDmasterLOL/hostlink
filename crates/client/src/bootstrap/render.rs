//! Target-local credential provisioning and source-pinned bootstrap rendering.

use super::validate::{ArtifactSelection, VerifiedInstaller};

// Reuse the actual installer functions; credential/download policy has one source per OS.
fn github_helpers(source: &str) -> &str {
    source
        .split_once("# BEGIN GITHUB BOOTSTRAP HELPERS\n")
        .expect("bundled bootstrap helper start")
        .1
        .split_once("# END GITHUB BOOTSTRAP HELPERS")
        .expect("bundled bootstrap helper end")
        .0
}

pub fn render_command(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
    render_command_with_token(selection, installer, None)
}

/// Embed a Controller PAT only after an explicit user opt-in at the CLI
/// boundary. The returned text is a credential and must not be logged.
pub(super) fn render_command_with_token(
    selection: &ArtifactSelection,
    installer: &VerifiedInstaller,
    token: Option<&str>,
) -> String {
    if selection.target.windows() {
        render_powershell(selection, installer, token)
    } else {
        render_posix(selection, installer, token)
    }
}

fn render_powershell(
    selection: &ArtifactSelection,
    installer: &VerifiedInstaller,
    token: Option<&str>,
) -> String {
    let digest = ps_quote(&installer.sha256);
    let url = ps_quote(installer.url.as_str());
    let args = [
        ("HubUrl", selection.hub_url.as_str()),
        ("Name", selection.name.as_str()),
        ("SshUser", selection.ssh_user.as_str()),
        ("AgentUri", selection.agent_url.as_str()),
        ("AgentSha256", selection.agent_sha256.as_str()),
        ("ArchiveUri", selection.archive_url.as_str()),
        ("ArchiveSha256", selection.archive_sha256.as_str()),
        ("AgentVersion", selection.version.as_str()),
        ("Target", selection.target.as_str()),
    ]
    .into_iter()
    .map(|(name, value)| format!(" -{name} {}", ps_quote(value)))
    .collect::<String>();
    let helpers = github_helpers(include_str!(
        "../../../agent/assets/Install-HostLink-Agent.ps1"
    ));
    let provision = token.map_or_else(
        || "[void](Get-GitHubCredential $true)".to_owned(),
        |token| format!("[void](Get-GitHubCredential $true {})", ps_quote(token)),
    );
    let script = format!(
        "$ErrorActionPreference='Stop'\nSet-PSDebug -Off\n{helpers}\nAssert-GitHubAsset {url}\n{provision}\n$bytes=Get-GitHubAsset {url} '' 1048576 30\n$h=New-Object Security.Cryptography.SHA256Managed\ntry{{$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}}finally{{$h.Clear()}}\nif($actual -cne {digest}){{throw 'Installer SHA-256 mismatch'}}\n$script=[Text.Encoding]::UTF8.GetString($bytes)\n& ([scriptblock]::Create($script)){args}\n"
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
        // Windows cmd.exe limits the entire encoded command to 8191 characters.
        // The security helpers cannot fit; provide an explicit two-step local helper.
        let note = if token.is_some() {
            "WARNING: This helper contains your GitHub PAT in plain text. Save it privately, never share it, and delete it after installation."
        } else {
            "No GitHub credential is included."
        };
        format!(
            "1. On the TARGET save the script between the markers as %USERPROFILE%\\hostlink-bootstrap.ps1 (UTF-8 with BOM). {note}\n2. In an unelevated target cmd.exe run:\npowershell -NoProfile -ExecutionPolicy Bypass -File \"%USERPROFILE%\\hostlink-bootstrap.ps1\"\n# BEGIN TARGET HELPER\n{script}# END TARGET HELPER\n"
        )
    }
}

fn render_posix(
    selection: &ArtifactSelection,
    installer: &VerifiedInstaller,
    token: Option<&str>,
) -> String {
    let mut args = [
        ("--hub-url", selection.hub_url.as_str()),
        ("--name", selection.name.as_str()),
        ("--ssh-user", selection.ssh_user.as_str()),
        ("--agent-url", selection.agent_url.as_str()),
        ("--agent-sha256", selection.agent_sha256.as_str()),
        ("--archive-url", selection.archive_url.as_str()),
        ("--archive-sha256", selection.archive_sha256.as_str()),
        ("--agent-version", selection.version.as_str()),
        ("--target", selection.target.as_str()),
    ]
    .into_iter()
    .map(|(name, value)| format!(" {} {}", sh_quote(name), sh_quote(value)))
    .collect::<String>();
    if let Some(path) = &selection.bootstrap_hub_ca_cert {
        args.push_str(&format!(
            " {} {}",
            sh_quote("--hub-ca-cert"),
            sh_quote(&path.to_string_lossy())
        ));
    }
    let helpers = github_helpers(include_str!(
        "../../../agent/assets/install-hostlink-agent.sh"
    ));
    let provision = token.map_or_else(
        || "hl_provision_credential".to_owned(),
        |token| format!("hl_provision_credential {}", sh_quote(token)),
    );
    format!(
        "set -eu\n{helpers}\nhl_asset_url {url}\n{provision}\ninstaller=$(mktemp)\ntrap 'rm -f \"$installer\"' EXIT\ntrap 'exit 130' HUP INT TERM\nhl_download {url} \"$installer\" 1048576 30\nprintf '%s  %s\\n' {digest} \"$installer\" | sha256sum -c -\n/bin/sh \"$installer\"{args}\n",
        url = sh_quote(installer.url.as_str()),
        digest = sh_quote(&installer.sha256),
    )
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
