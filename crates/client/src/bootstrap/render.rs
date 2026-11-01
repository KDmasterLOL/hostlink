//! Copyable PowerShell 2/Win7 and POSIX bootstrap command rendering.

use super::validate::{ArtifactSelection, VerifiedInstaller};

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
    let script = format!(
        "$ErrorActionPreference='Stop'; $tls=[Enum]::ToObject([Net.SecurityProtocolType],3072); [Net.ServicePointManager]::SecurityProtocol=$tls; $u=New-Object Uri({url}); if($u.Scheme -cne 'https'){{throw 'HTTPS required'}}; $r=[Net.HttpWebRequest]::Create($u); $r.AllowAutoRedirect=$false; $r.Timeout=30000; $r.ReadWriteTimeout=30000; $v=$r.GetResponse(); try{{if([int]$v.StatusCode -ne 200 -or $v.ContentLength -gt 1048576){{throw 'Pinned installer response rejected'}}; $s=$v.GetResponseStream(); $m=New-Object IO.MemoryStream; $b=New-Object byte[] 65536; while(($n=$s.Read($b,0,$b.Length)) -gt 0){{if($m.Length+$n -gt 1048576){{throw 'Installer too large'}}; $m.Write($b,0,$n)}}; $bytes=$m.ToArray()}}finally{{$v.Close()}}; $h=New-Object Security.Cryptography.SHA256Managed; try{{$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}}finally{{$h.Clear()}}; if($actual -cne {digest}){{throw 'Installer SHA-256 mismatch'}}; $script=[Text.Encoding]::UTF8.GetString($bytes); & ([scriptblock]::Create($script)){args}\n",
        args = args
    );
    let utf16le = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, utf16le)
    )
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
    let curl_ca = selection
        .bootstrap_hub_ca_cert
        .as_ref()
        .map(|path| format!("--cacert {} ", sh_quote(&path.to_string_lossy())))
        .unwrap_or_default();
    format!(
        "set -eu\ninstaller=$(mktemp)\ntrap 'rm -f \"$installer\"' EXIT HUP INT TERM\ncurl {curl_ca}--fail --silent --show-error --proto '=https' --tlsv1.2 --max-filesize 1048576 --connect-timeout 10 --max-time 30 -o \"$installer\" {}\nprintf '%s  %s\\n' {} \"$installer\" | sha256sum -c -\n/bin/sh \"$installer\"{}\n",
        sh_quote(installer.url.as_str()),
        sh_quote(&installer.sha256),
        args,
        curl_ca = curl_ca
    )
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
