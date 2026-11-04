//! Packed, secret-bearing bootstrap commands. Preflight happens before Hub issuance.
use std::io::Write;

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};

use super::{ArtifactSelection, BootstrapError, Target};

const PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CMD_LIMIT: usize = 8191;

pub struct InlineBootstrap(String, usize);

impl InlineBootstrap {
    /// Bind the Hub token without altering the preflighted command length.
    pub fn bind(self, token: &str) -> Result<String, BootstrapError> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BootstrapError::Invalid(
                "Hub invitation token has an invalid format",
            ));
        }
        let mut command = self.0;
        command.replace_range(self.1..self.1 + PLACEHOLDER.len(), token);
        Ok(command)
    }
}

fn quote_ps(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
fn quote_sh(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Prepare and length-check a command before creating a one-use invitation.
pub fn prepare_inline(selections: &[ArtifactSelection]) -> Result<InlineBootstrap, BootstrapError> {
    render_inline(selections)
}

fn render_inline(selections: &[ArtifactSelection]) -> Result<InlineBootstrap, BootstrapError> {
    let first = selections
        .first()
        .ok_or(BootstrapError::Invalid("missing release assets"))?;
    for s in selections {
        s.validate()?;
    }
    for (index, selection) in selections.iter().enumerate() {
        if selections[..index]
            .iter()
            .any(|previous| previous.target == selection.target)
            || selection.name != first.name
            || selection.ssh_user != first.ssh_user
            || selection.hub_url != first.hub_url
            || selection.bootstrap_hub_ca_cert != first.bootstrap_hub_ca_cert
            || selection.gateway_index != first.gateway_index
            || selection.agent_url.path().split('/').nth(5)
                != first.agent_url.path().split('/').nth(5)
        {
            return Err(BootstrapError::Invalid(
                "inconsistent or duplicate release selections",
            ));
        }
    }
    let ca = first
        .bootstrap_hub_ca_cert
        .as_deref()
        .map(|p| p.to_string_lossy())
        .unwrap_or_default();
    let gateway = first
        .gateway_index
        .map(|n| n.to_string())
        .unwrap_or_default();
    let windows = first.target.windows();
    let script = if windows {
        if selections.len() != 1 && selections.len() != 3 {
            return Err(BootstrapError::Invalid(
                "incomplete Windows release selection",
            ));
        }
        let mut vars = String::new();
        for (key, value) in [
            ("HubUrl", first.hub_url.as_str()),
            ("Name", first.name.as_str()),
            ("SshUser", first.ssh_user.as_str()),
            ("HubCaCert", ca.as_ref()),
            ("GatewayIndex", gateway.as_str()),
        ] {
            vars.push_str(&format!("${key}={}\n", quote_ps(value)));
        }
        let tag = first
            .agent_url
            .path()
            .split('/')
            .nth(5)
            .ok_or(BootstrapError::Invalid("missing release tag"))?;
        vars.push_str(&format!(
            "$ReleaseTag={}\n$RequestedTarget={}\n",
            quote_ps(tag),
            quote_ps(if selections.len() == 1 {
                first.target.as_str()
            } else {
                ""
            })
        ));
        vars.push_str("$ShaWin7X86=''\n$ShaWin7X64=''\n$ShaWin11X64=''\n");
        for selection in selections {
            let key = match selection.target {
                Target::Win7X86 => "ShaWin7X86",
                Target::Win7X64 => "ShaWin7X64",
                Target::Win11X64 => "ShaWin11X64",
                Target::LinuxX64 => {
                    return Err(BootstrapError::Invalid("invalid Windows release selection"));
                }
            };
            vars.push_str(&format!("${key}={}\n", quote_ps(&selection.agent_sha256)));
        }
        let body = include_str!("../../../assets/bootstrap-windows.ps1");
        format!(
            "$Invite=$args[0]\n$ErrorActionPreference='Stop'\nSet-PSDebug -Off\n$a=$env:PROCESSOR_ARCHITECTURE;if($env:PROCESSOR_ARCHITEW6432){{$a=$env:PROCESSOR_ARCHITEW6432}};if(@('AMD64','x86') -notcontains $a){{throw 'Unsupported architecture.'}}\n{}\n{vars}\n{body}",
            include_str!("../../../assets/github-windows.ps1")
        )
    } else {
        if selections.len() != 1 || first.target != Target::LinuxX64 {
            return Err(BootstrapError::Invalid("invalid Linux release selection"));
        }
        let mut vars = String::new();
        for (key, value) in [
            ("hub_url", first.hub_url.as_str()),
            ("name", first.name.as_str()),
            ("ssh_user", first.ssh_user.as_str()),
            ("hub_ca_cert", ca.as_ref()),
            ("gateway_index", gateway.as_str()),
            ("agent_url", first.agent_url.as_str()),
            ("agent_sha256", first.agent_sha256.as_str()),
        ] {
            vars.push_str(&format!("{key}={}\n", quote_sh(value)));
        }
        let body = include_str!("../../../assets/bootstrap-posix.sh");
        format!(
            "set -eu\ngetconf GNU_LIBC_VERSION >/dev/null 2>&1 || {{ echo glibc-required >&2; exit 1; }}\n{}\n{vars}\n{body}",
            include_str!("../../../assets/github-posix.sh")
        )
    };
    let script = if windows {
        let compact = script
            .lines()
            .map(str::trim_start)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        shorten_errors(&compact)
    } else {
        script
    };
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(script.as_bytes())
        .map_err(|_| BootstrapError::Invalid("bootstrap compression failed"))?;
    let payload = STANDARD.encode(
        gzip.finish()
            .map_err(|_| BootstrapError::Invalid("bootstrap compression failed"))?,
    );
    let command = if windows {
        format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"& ([ScriptBlock]::Create((New-Object IO.StreamReader((New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String('{payload}'))),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::UTF8)).ReadToEnd())) '{PLACEHOLDER}'\""
        )
    } else {
        format!(
            "(HL_INVITE='{PLACEHOLDER}';export HL_INVITE;HL_SCRIPT=$(printf %s '{payload}' | base64 -d | gzip -d) && sh -c \"$HL_SCRIPT\")"
        )
    };
    if windows && command.len() > CMD_LIMIT {
        return Err(BootstrapError::Invalid(
            "inline bootstrap exceeds cmd.exe 8191 character limit",
        ));
    }
    // The placeholder is at the end of the Windows command and at the start
    // of the POSIX command, independently of the compressed payload contents.
    let token_offset = if windows {
        command.len() - 2 - PLACEHOLDER.len()
    } else {
        "(HL_INVITE='".len()
    };
    debug_assert_eq!(
        &command[token_offset..token_offset + PLACEHOLDER.len()],
        PLACEHOLDER
    );
    Ok(InlineBootstrap(command, token_offset))
}

// Long diagnostics dominate the compressed command. Keep an identifiable prefix
// without changing the checks or control flow; all such literals are ASCII.
fn shorten_errors(script: &str) -> String {
    let mut out = String::new();
    let mut rest = script;
    while let Some(index) = rest.find("throw '") {
        let (prefix, tail) = rest.split_at(index + 7);
        out.push_str(prefix);
        let Some(end) = tail.find('\'') else {
            out.push_str(tail);
            return out;
        };
        let message = &tail[..end];
        if message.is_ascii() && message.len() > 38 {
            out.push_str(&message[..35]);
            out.push_str("...");
        } else {
            out.push_str(message);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[path = "inline_tests.rs"]
mod tests;
