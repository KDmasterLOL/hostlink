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
                assert!(script.contains("$os.BuildNumber -ge 10240"));
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
                assert!(script.contains("hl_download \"$agent_url\" \"$agent\" 268435456 600"));
                assert!(script.contains("--proto '=https' --tlsv1.2"));
                assert!(script.contains(
                    "release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*"
                ));
                assert!(
                    script.find("sha256sum -c -").unwrap()
                        < script
                            .find("(set -C; printf '%s' \"$HL_INVITE\" > \"$token_file\")")
                            .unwrap()
                );
                assert!(
                    script
                        .find("(set -C; printf '%s' \"$HL_INVITE\" > \"$token_file\")")
                        .unwrap()
                        < script.find("\"$agent\" \"$@\"").unwrap()
                );
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

#[cfg(unix)]
#[test]
fn posix_transfer_failure_cleans_partial_without_creating_invite_token() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let curl = dir.path().join("curl");
    fs::write(
        &curl,
        r##"#!/bin/sh
if [ "$2" = --version ]; then echo 'curl 8.4.0'; exit 0; fi
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then shift; out=$1; fi
    shift
done
printf partial > "$out"
exit 28
"##,
    )
    .unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();

    let rm = dir.path().join("rm");
    fs::write(
        &rm,
        r##"#!/bin/sh
if [ "$1" = -rf ]; then
    if [ -e "$2/invite-token" ]; then printf token-present > "$HL_RM_LOG"; else printf no-token > "$HL_RM_LOG"; fi
fi
exec /bin/rm "$@"
"##,
    )
    .unwrap();
    fs::set_permissions(&rm, fs::Permissions::from_mode(0o700)).unwrap();

    let command = render_inline(&selections(&[Target::LinuxX64]))
        .unwrap()
        .bind(&"a".repeat(64))
        .unwrap();
    let rm_log = dir.path().join("rm-log");
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("HOME", dir.path())
        .env("TMPDIR", dir.path())
        .env("HL_RM_LOG", &rm_log)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("GitHub asset download failed"));
    assert_eq!(fs::read_to_string(rm_log).unwrap(), "no-token");
    assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("hostlink-bootstrap.")
    }));
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
    assert!(
        Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&safe_command)
            .status()
            .unwrap()
            .success()
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
fn selections_must_be_unique_and_share_release_and_invitation_parameters() {
    assert!(render_inline(&[]).is_err());
    let assets = selections(&[Target::Win7X86, Target::Win7X64, Target::Win11X64]);
    assert!(render_inline(&assets[..2]).is_err());
    let mut duplicate = assets.clone();
    duplicate.push(assets[0].clone());
    assert!(render_inline(&duplicate).is_err());
    for field in 0..6 {
        let mut mixed = assets.clone();
        match field {
            0 => mixed[1].name = "other".into(),
            1 => mixed[1].ssh_user = "other".into(),
            2 => mixed[1].hub_url = "https://other.example".into(),
            3 => mixed[1].bootstrap_hub_ca_cert = Some("other".into()),
            4 => mixed[1].gateway_index = None,
            _ => {
                mixed[1].agent_url = Url::parse(&format!(
                    "https://github.com/KDmasterLOL/hostlink/releases/download/v2.0.0/{}",
                    mixed[1].target.asset_name()
                ))
                .unwrap()
            }
        }
        assert!(render_inline(&mixed).is_err(), "field {field}");
    }
}

#[test]
fn binding_uses_token_position_even_if_placeholder_occurs_earlier() {
    let mut prepared = render_inline(&selections(&[Target::Win7X64])).unwrap();
    prepared.0.insert_str(0, PLACEHOLDER);
    prepared.1 += PLACEHOLDER.len();
    let command = prepared.bind(&"a".repeat(64)).unwrap();
    assert!(command.starts_with(PLACEHOLDER));
    assert_eq!(
        &command[command.len() - 66..command.len() - 2],
        "a".repeat(64)
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
    // Exercise sha256sum's checksum-file format with a valid unusual TMPDIR.
    let tmp = dir.path().join("tmp\\with\nnewline");
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

// Keep the real wrapper and complete bootstrap body, but return before any
// bootstrap operation. PowerShell must parse the whole body before running it.
fn windows_parser_fixture() -> String {
    let token = "a".repeat(64);
    let command = render_inline(&selections(&[
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ]))
    .unwrap()
    .bind(&token)
    .unwrap();
    let script = unpack(&command);
    let (first, rest) = script.split_once('\n').unwrap();
    assert_eq!(first, "$Invite=$args[0]");
    let guard = format!(
        "if ($Invite -cne '{token}') {{ throw 'Synthetic token binding failed' }}\nif ('Проверка' -cne ([string][char]0x41f + [char]0x440 + [char]0x43e + [char]0x432 + [char]0x435 + [char]0x440 + [char]0x43a + [char]0x430)) {{ throw 'Synthetic UTF8 decoding failed' }}\nWrite-Output 'HOSTLINK_SYNTHETIC_PARSER_OK'\nreturn"
    );
    let safe_script = format!("{first}\n{guard}\n{rest}");
    let mut gzip = GzEncoder::new(Vec::new(), Compression::best());
    gzip.write_all(safe_script.as_bytes()).unwrap();
    let payload = STANDARD.encode(gzip.finish().unwrap());
    let start = command.find("FromBase64String('").unwrap() + "FromBase64String('".len();
    let end = start + command[start..].find('\'').unwrap();
    let fixture = format!("{}{}{}", &command[..start], payload, &command[end..]);
    assert!(fixture.len() <= CMD_LIMIT);
    fixture
}

#[test]
fn windows_synthetic_parser_fixture_preserves_wrapper_and_stops_before_bootstrap() {
    let fixture = windows_parser_fixture();
    let original = render_inline(&selections(&[
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ]))
    .unwrap()
    .bind(&"a".repeat(64))
    .unwrap();
    let payload_span = |s: &str| {
        let start = s.find("FromBase64String('").unwrap() + "FromBase64String('".len();
        let end = start + s[start..].find('\'').unwrap();
        (start, end)
    };
    let (a, b) = payload_span(&original);
    let (c, d) = payload_span(&fixture);
    assert_eq!(&original[..a], &fixture[..c]);
    assert_eq!(&original[b..], &fixture[d..]);
    assert!(!fixture.contains('$'));
    assert!(!fixture.contains('%') && !fixture.contains('!'));
    assert!(fixture.starts_with("powershell -NoProfile -ExecutionPolicy Bypass -Command \"& ("));
    assert!(fixture.ends_with(&format!(" '{0}'\"", "a".repeat(64))));
    assert_eq!(fixture.matches('"').count(), 2);
    let script = unpack(&fixture);
    let marker = "Write-Output 'HOSTLINK_SYNTHETIC_PARSER_OK'\nreturn\n";
    let (guard, tail) = script.split_once(marker).unwrap();
    assert!(guard.starts_with("$Invite=$args[0]\nif ($Invite -cne"));
    assert_eq!(tail, original_script_tail(&original));

    // Opt-in artifact generation: no file is created during ordinary tests.
    if let Some(path) = std::env::var_os("HOSTLINK_SYNTHETIC_WINDOWS_FIXTURE") {
        std::fs::write(path, format!("{fixture}\n")).unwrap();
    }
}

fn original_script_tail(command: &str) -> String {
    unpack(command).split_once('\n').unwrap().1.to_owned()
}

// Feed the actual paste line to each shell on stdin. In particular, do not
// pass it as a cmd /C argument: Windows argv quoting changes that input.
#[cfg(windows)]
#[test]
fn windows_synthetic_fixture_runs_as_shell_input() {
    use std::process::{Command, Stdio};

    let fixture = windows_parser_fixture();
    for (program, args) in [
        ("cmd.exe", &["/D", "/Q"][..]),
        (
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", "-"][..],
        ),
    ] {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{fixture}").unwrap();
        if program == "cmd.exe" {
            writeln!(input, "exit").unwrap();
        }
        drop(input);
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{program}: {stderr}");
        // The marker is compressed in the input, so shell prompts cannot
        // produce a false positive even if a prompt shares the output line.
        assert!(
            stdout.contains("HOSTLINK_SYNTHETIC_PARSER_OK"),
            "{program}: {stdout} {stderr}"
        );
    }
}

#[test]
fn windows_native_download_guards_precede_token_and_install() {
    let assets = selections(&[Target::Win7X86, Target::Win7X64, Target::Win11X64]);
    let script = unpack(
        &render_inline(&assets)
            .unwrap()
            .bind(&"a".repeat(64))
            .unwrap(),
    );
    for asset in &assets {
        assert!(script.contains(&asset.agent_sha256));
    }
    let native = script
        .split("function Get-Win7Asset")
        .nth(1)
        .unwrap()
        .split("function Get-GitHubAsset")
        .next()
        .unwrap();
    assert!(native.contains("[uint32]2217476096")); // 0x842c0000
    assert!(native.contains("$status -ne 302 -or $hop -ne 0"));
    assert!(native.contains("release-assets|objects"));
    assert!(native.contains("$total -gt $MaximumBytes"));
    assert!(
        native.find("$total -gt $MaximumBytes").unwrap()
            < native.find("$output.Write($buffer").unwrap()
    );
    assert!(native.contains("$created -and -not $complete"));
    assert!(native.contains("InternetCloseHandle($request)"));
    assert!(native.contains("InternetCloseHandle($session)"));
    assert!(
        script.find("Get-Win7Asset $AgentUri $agentFile").unwrap()
            < script.find("ComputeHash($stream)").unwrap()
    );
    assert!(
        script.find("ComputeHash($stream)").unwrap()
            < script.find("Write-PrivateSecret $tokenFile").unwrap()
    );
    assert!(
        script.find("Write-PrivateSecret $tokenFile").unwrap()
            < script.find("& $agentFile @installArgs").unwrap()
    );
}
