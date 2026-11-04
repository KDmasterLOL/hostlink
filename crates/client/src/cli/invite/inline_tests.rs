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

#[cfg(target_os = "linux")]
#[test]
fn actual_posix_command_runs_offline_and_cleans_failures() {
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let tmp = dir.path().join("tmp");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&tmp).unwrap();
    let agent = dir.path().join("synthetic-agent");
    let agent_script = r##"#!/bin/sh
set -eu
if [ "$1" = install ]; then
    [ "$FIXTURE_MODE" != agent_fail ] || exit 1
    shift
    while [ "$#" -gt 0 ]; do
        if [ "$1" = --token-file ]; then shift; token=$1; fi
        if [ "$1" = --hub-ca-cert ]; then shift; printf '%s' "$1" > "$FIXTURE_CA"; fi
        shift
    done
    [ "$(stat -c %a "$token")" = 600 ]
    [ "$(cat "$token")" = "$(printf '%064d' 0 | tr 0 a)" ]
    printf install >> "$FIXTURE_LOG"
    mkdir -p "$XDG_DATA_HOME/hostlink/Agent/bin"
    cp "$FIXTURE_AGENT" "$XDG_DATA_HOME/hostlink/Agent/bin/hostlink-agent"
else
    printf ' %s' "$2" >> "$FIXTURE_LOG"
fi
"##;
    fs::write(&agent, agent_script).unwrap();
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o700)).unwrap();
    let curl = bin.join("curl");
    fs::write(&curl, r##"#!/bin/sh
set -eu
if [ "$2" = --version ]; then echo 'curl 8.4.0'; exit; fi
out= url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) shift; out=$1 ;;
        --location|--location-trusted|*[Aa]uthorization*) exit 91 ;;
        https://*) url=$1 ;;
    esac
    shift
done
printf '%s\n' "$url" >> "$FIXTURE_URLS"
case "$FIXTURE_MODE" in
    download_fail) exit 22 ;;
    unsafe_redirect) printf '302\nhttps://evil.invalid/asset'; exit ;;
    redirect) case "$url" in
        https://github.com/*) printf '302\nhttps://release-assets.githubusercontent.com/synthetic'; exit ;;
        https://release-assets.githubusercontent.com/*) ;;
        *) exit 92 ;;
    esac ;;
esac
cp "$FIXTURE_AGENT" "$out"
printf '200\n'
"##).unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();
    let mut assets = selections(&[Target::LinuxX64]);
    assets[0].agent_sha256 = format!("{:x}", Sha256::digest(agent_script.as_bytes()));
    assets[0].bootstrap_hub_ca_cert = Some("a'b;$(touch should-not-exist)".into());
    let command = render_inline(&assets)
        .unwrap()
        .bind(&"a".repeat(64))
        .unwrap();
    assert!(!command.contains('\n'));
    let syntax = Command::new("sh")
        .args(["-n", "-c", &command])
        .status()
        .unwrap();
    assert!(syntax.success());
    for mode in [
        "redirect",
        "download_fail",
        "unsafe_redirect",
        "bad_digest",
        "agent_fail",
    ] {
        let log = dir.path().join("log");
        let urls = dir.path().join("urls");
        let ca = dir.path().join("ca");
        let _ = fs::remove_file(&log);
        let _ = fs::remove_file(&urls);
        let mut selected = assets.clone();
        if mode == "bad_digest" {
            selected[0].agent_sha256 = "0".repeat(64);
        }
        let command = render_inline(&selected)
            .unwrap()
            .bind(&"a".repeat(64))
            .unwrap();
        let output = Command::new("sh").arg("-c")
            .arg(format!("HL_INVITE=parent; HL_SCRIPT=parent; {command}; result=$?; [ \"$HL_INVITE\" = parent ] && [ \"$HL_SCRIPT\" = parent ] || exit 99; exit \"$result\""))
            .current_dir(dir.path()).env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", dir.path()).env("XDG_DATA_HOME", dir.path().join("data"))
            .env("TMPDIR", &tmp).env("FIXTURE_AGENT", &agent).env("FIXTURE_LOG", &log)
            .env("FIXTURE_URLS", &urls).env("FIXTURE_CA", &ca).env("FIXTURE_MODE", mode)
            .output().unwrap();
        assert_eq!(
            output.status.success(),
            mode == "redirect",
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0, "{mode}");
        assert!(!dir.path().join("should-not-exist").exists());
        if mode == "redirect" {
            assert_eq!(fs::read_to_string(&log).unwrap(), "install install start");
            assert_eq!(
                fs::read_to_string(&ca).unwrap(),
                "a'b;$(touch should-not-exist)"
            );
            let urls = fs::read_to_string(&urls).unwrap();
            assert_eq!(urls.lines().count(), 2);
            assert!(urls.starts_with("https://github.com/KDmasterLOL/hostlink/releases/download/"));
        } else {
            assert!(!log.exists(), "agent ran on {mode}");
        }
    }
}
