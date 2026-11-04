use super::*;
use flate2::read::GzDecoder;
use reqwest::Url;
use std::io::Read;

fn selections(targets: &[Target]) -> Vec<ArtifactSelection> {
    targets
        .iter()
        .enumerate()
        .map(|(i, &target)| ArtifactSelection {
            agent_url: Url::parse(&format!(
                "https://github.com/KDmasterLOL/hostlink/releases/download/v1.2.3/{}",
                target.asset_name()
            ))
            .unwrap(),
            agent_sha256: (0..64)
                .map(|j| b"0123456789abcdef"[(j * 7 + i) % 16] as char)
                .collect(),
            target,
            name: "n".repeat(128),
            ssh_user: "u".repeat(128),
            hub_url: "https://hub.example".into(),
            bootstrap_hub_ca_cert: None,
            gateway_index: Some(123456),
        })
        .collect()
}
fn unpack(command: &str) -> String {
    let encoded = if command.starts_with("powershell") {
        command
            .split("FromBase64String('")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap()
    } else {
        command
            .split("printf %s '")
            .nth(1)
            .unwrap()
            .split('\'')
            .next()
            .unwrap()
    };
    let mut script = String::new();
    GzDecoder::new(STANDARD.decode(encoded).unwrap().as_slice())
        .read_to_string(&mut script)
        .unwrap();
    script
}
#[test]
fn inline_commands_bind_fixed_token_and_verify_before_install() {
    for targets in [
        &[Target::Win7X86, Target::Win7X64, Target::Win11X64][..],
        &[Target::LinuxX64][..],
    ] {
        {
            let prepared = render_inline(&selections(targets)).unwrap();
            let command = prepared.bind(&"a".repeat(64)).unwrap();
            assert!(!command.contains('\n'));
            if targets[0].windows() {
                assert!(command.len() <= CMD_LIMIT, "{}", command.len());
            }
            let script = unpack(&command);
            if targets[0].windows() {
                assert!(script.contains("SHA256Managed"));
                assert!(script.contains("$request.AllowAutoRedirect = $false"));
                assert!(!script.contains("Authorization"));
                assert!(script.contains("SetAccessRuleProtection($true, $false)"));
                assert!(script.contains("Read-Host $Prompt -AsSecureString"));
                assert!(script.contains("$version.Major -eq 6 -and $version.Minor -eq 1"));
                assert!(script.contains("$os.BuildNumber -ge 22000"));
                assert!(
                    script.find("Agent executable SHA-256 mismatch").unwrap()
                        < script.find("Write-PrivateSecret $tokenFile").unwrap()
                );
                assert!(script.contains("service start --root"));
                assert!(!script.contains("$NoRun"));
            } else {
                assert!(
                    script.find("sha256sum -c -").unwrap()
                        < script.find("\"$agent\" \"$@\"").unwrap()
                );
                assert!(!script.contains("One-use HostLink invite token:"));
                assert!(script.contains("service start --root"));
                assert!(script.contains("umask 077"));
                assert!(script.contains("(set -C; printf '%s' \"$HL_INVITE\" > \"$token_file\")"));
                assert!(script.contains("trap cleanup 0"));
                assert!(script.contains("curl -q"));
                assert!(!script.contains("--location"));
                assert!(command.starts_with("(HL_INVITE="));
                assert!(command.ends_with(')'));
                #[cfg(unix)]
                {
                    use std::process::{Command, Stdio};
                    let mut shell = Command::new("sh")
                        .arg("-n")
                        .stdin(Stdio::piped())
                        .spawn()
                        .unwrap();
                    shell
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(script.as_bytes())
                        .unwrap();
                    assert!(shell.wait().unwrap().success());
                }
            }
        }
    }
    assert!(
        render_inline(&selections(&[Target::LinuxX64]))
            .unwrap()
            .bind("bad")
            .is_err()
    );
}

#[test]
fn quoted_target_paths_and_gateway_are_in_the_packed_script() {
    for target in [Target::Win7X64, Target::LinuxX64] {
        let mut assets = selections(&[target]);
        assets[0].bootstrap_hub_ca_cert = Some("a'b;$(touch /tmp/not-executed)".into());
        assets[0].gateway_index = Some(12);
        let output = render_inline(&assets)
            .unwrap()
            .bind(&"a".repeat(64))
            .unwrap();
        let script = unpack(&output);
        if target.windows() {
            assert!(script.contains("$HubCaCert='a''b;$(touch /tmp/not-executed)'"));
            assert!(script.contains("$GatewayIndex='12'"));
            assert!(!script.contains("Get-GitHubCredential"));
        } else {
            assert!(script.contains("hub_ca_cert='a'\\''b;$(touch /tmp/not-executed)'"));
            assert!(script.contains("gateway_index='12'"));
            assert!(!script.contains("hl_provision_credential"));
        }
    }
}

#[cfg(unix)]
#[test]
fn posix_token_creation_refuses_overwrite_and_command_keeps_parent_environment() {
    use std::{fs, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let token_file = temp.path().join("invite-token");
    fs::write(&token_file, "original").unwrap();
    let script = unpack(&render_inline(&selections(&[Target::LinuxX64])).unwrap().0);
    let create = script
        .lines()
        .find(|line| line.starts_with("(set -C; printf '%s' \"$HL_INVITE\""))
        .unwrap();
    let status = Command::new("sh")
        .arg("-c")
        .arg(create)
        .env("token_file", &token_file)
        .env("HL_INVITE", "synthetic")
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(&token_file).unwrap(), "original");

    let command = render_inline(&selections(&[Target::LinuxX64]))
        .unwrap()
        .bind(&"a".repeat(64))
        .unwrap();
    let start = command.find("printf %s '").unwrap() + "printf %s '".len();
    let end = start + command[start..].find('\'').unwrap();
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(b"exit 0\n").unwrap();
    let safe_command = format!(
        "{}{}{}",
        &command[..start],
        STANDARD.encode(gzip.finish().unwrap()),
        &command[end..]
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "HL_INVITE=parent; {safe_command}; printf %s \"$HL_INVITE\""
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"parent");
}

#[test]
fn windows_length_is_checked_with_incompressible_digests() {
    let mut state = 0x12345678u32;
    let mut assets = selections(&[Target::Win7X86, Target::Win7X64, Target::Win11X64]);
    for asset in &mut assets {
        asset.agent_sha256 = (0..64)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                b"0123456789abcdef"[(state as usize) % 16] as char
            })
            .collect();
    }
    let result = render_inline(&assets);
    let command = result.expect("synthetic digest command must fit");
    eprintln!("synthetic Windows command length: {}", command.0.len());
    assert!(command.0.len() <= CMD_LIMIT);
}

#[test]
fn oversized_windows_command_is_rejected_before_binding() {
    let mut assets = selections(&[Target::Win7X86, Target::Win7X64, Target::Win11X64]);
    let mut state = 0x76543210u32;
    let path: String = (0..12000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[state as usize % 62]
                as char
        })
        .collect();
    for asset in &mut assets {
        asset.bootstrap_hub_ca_cert = Some(path.clone().into());
    }
    assert!(
        render_inline(&assets)
            .err()
            .unwrap()
            .to_string()
            .contains("8191")
    );
}

#[test]
fn windows_wrapper_passes_synthetic_invite_without_parent_expansion() {
    let command = render_inline(&selections(&[
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ]))
    .unwrap()
    .bind(&"a".repeat(64))
    .unwrap();
    assert_eq!(command.matches(&"a".repeat(64)).count(), 1);
    assert!(!command.contains('$'));
    assert!(unpack(&command).contains("$Invite=$args[0]"));
    assert!(command.len() <= CMD_LIMIT);
}
