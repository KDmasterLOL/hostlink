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
    if selection.target.windows() {
        render_powershell(selection, installer)
    } else {
        render_posix(selection, installer)
    }
}

fn render_powershell(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
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
    let script = format!(
        "$ErrorActionPreference='Stop'\nSet-PSDebug -Off\n{helpers}\nAssert-GitHubAsset {url}\n[void](Get-GitHubCredential $true)\n$bytes=Get-GitHubAsset {url} '' 1048576 30\n$h=New-Object Security.Cryptography.SHA256Managed\ntry{{$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}}finally{{$h.Clear()}}\nif($actual -cne {digest}){{throw 'Installer SHA-256 mismatch'}}\n$script=[Text.Encoding]::UTF8.GetString($bytes)\n& ([scriptblock]::Create($script)){args}\n"
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
        format!(
            "1. On the TARGET save the script between the markers as %USERPROFILE%\\hostlink-bootstrap.ps1 (UTF-8 with BOM). No credential is included.\n2. In an unelevated target cmd.exe run:\npowershell -NoProfile -ExecutionPolicy Bypass -File \"%USERPROFILE%\\hostlink-bootstrap.ps1\"\n# BEGIN TARGET HELPER\n{script}# END TARGET HELPER\n"
        )
    }
}

fn render_posix(selection: &ArtifactSelection, installer: &VerifiedInstaller) -> String {
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
    format!(
        "set -eu\n{helpers}\nhl_asset_url {url}\nhl_provision_credential\ninstaller=$(mktemp)\ntrap 'rm -f \"$installer\"' EXIT\ntrap 'exit 130' HUP INT TERM\nhl_download {url} \"$installer\" 1048576 30\nprintf '%s  %s\\n' {digest} \"$installer\" | sha256sum -c -\n/bin/sh \"$installer\"{args}\n",
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
