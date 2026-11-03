use super::*;
use reqwest::Url;

fn selection(target: Target) -> ArtifactSelection {
    ArtifactSelection {
        agent_url: Url::parse(
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/102",
        )
        .unwrap(),
        agent_sha256: "b".repeat(64),
        target,
        name: "lab-host".into(),
        ssh_user: "hostlink".into(),
        hub_url: "https://hub.example".into(),
        bootstrap_hub_ca_cert: None,
        gateway_index: None,
    }
}

fn windows_script(output: &str) -> &str {
    output
        .split_once("# BEGIN TARGET HELPER\n")
        .unwrap()
        .1
        .split_once("# END TARGET HELPER")
        .unwrap()
        .0
}

#[test]
fn windows_output_requires_explicit_private_temporary_helper_execution() {
    for target in [Target::Win7X86, Target::Win7X64, Target::Win11X64] {
        for token in [None, Some("github_pat_synthetic_fixture_123")] {
            let output = super::render::render_command_with_token(&selection(target), token);
            assert_eq!(output.matches("# BEGIN TARGET HELPER\n").count(), 1);
            assert_eq!(output.matches("# END TARGET HELPER\n").count(), 1);
            assert!(output.ends_with("# END TARGET HELPER\n"));
            let instructions = output.split_once("# BEGIN TARGET HELPER\n").unwrap().0;
            assert!(instructions.contains("only the current user can read or modify it"));
            assert!(instructions.contains("Save ONLY the script between the markers"));
            assert!(instructions.contains("(UTF-8 with BOM)"));
            assert!(instructions.contains("Review the saved helper, then explicitly run"));
            assert!(instructions.contains("unelevated target cmd.exe"));
            assert!(instructions.contains("optionally append -NoRun"));
            assert!(
                instructions.contains(
                    "Delete the helper after installation, including if installation fails"
                )
            );
            assert_eq!(
                instructions
                    .lines()
                    .filter(|line| line.starts_with("powershell "))
                    .collect::<Vec<_>>(),
                [
                    "powershell -NoProfile -ExecutionPolicy Bypass -File \"%TEMP%\\hostlink-bootstrap.ps1\""
                ]
            );
            assert!(windows_script(&output).starts_with("param([switch]$NoRun)\n"));
            if token.is_some() {
                assert!(instructions.contains("GitHub PAT in plain text. Never share it."));
            } else {
                assert!(instructions.contains("No GitHub credential is included."));
            }
        }
    }
}

#[test]
fn four_exact_raw_asset_names_and_fixed_api_digest_pins() {
    for (target, asset) in [
        (Target::LinuxX64, "hostlink-agent-x86_64-unknown-linux-gnu"),
        (Target::Win7X86, "hostlink-agent-i686-win7-windows-msvc.exe"),
        (
            Target::Win7X64,
            "hostlink-agent-x86_64-win7-windows-msvc.exe",
        ),
        (
            Target::Win11X64,
            "hostlink-agent-x86_64-pc-windows-msvc.exe",
        ),
    ] {
        assert_eq!(Target::parse(target.as_str()).unwrap(), target);
        assert_eq!(target.asset_name(), asset);
        selection(target).validate().unwrap();
    }
    assert!(Target::parse("automatic").is_err());
    for url in [
        "https://elsewhere.invalid/asset",
        "https://api.github.com/repos/other/hostlink/releases/assets/1",
        "http://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://user@api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com:444/repos/KDmasterLOL/hostlink/releases/assets/1",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/0",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/%31",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1?x=1",
        "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/1#frag",
    ] {
        let mut selected = selection(Target::LinuxX64);
        selected.agent_url = Url::parse(url).unwrap();
        assert!(selected.validate().is_err(), "{url}");
    }
    for digest in [String::new(), "B".repeat(64), "b".repeat(63)] {
        let mut selected = selection(Target::LinuxX64);
        selected.agent_sha256 = digest;
        assert!(selected.validate().is_err());
    }
}

#[test]
fn bootstraps_verify_one_binary_before_invite_prompt_and_rust_install() {
    for target in [
        Target::LinuxX64,
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ] {
        let output = render_command(&selection(target));
        for removed in [
            ".zip",
            "bootstrap-verify",
            "bootstrap-finalize",
            "archive.sha256",
            "manifest.json",
            "bootstrap-receipt",
            "--root",
            "--retain-pending",
            "agent/assets",
        ] {
            assert!(!output.contains(removed), "obsolete {removed}");
        }
        if target.windows() {
            let script = windows_script(&output);
            let download = script.rfind("    Get-GitHubAsset ").unwrap();
            let digest = script.rfind("Agent executable SHA-256 mismatch").unwrap();
            let prompt = script.rfind("    [void](Write-PrivateSecret ").unwrap();
            let install = script.find("& $agentFile @installArgs").unwrap();
            assert!(download < digest && digest < prompt && prompt < install);
            assert!(script.contains("'HostLink\\Agent'"));
            assert!(script.contains("'bin\\hostlink-agent.exe'"));
            assert!(script.contains("param([switch]$NoRun)"));
            assert!(script.contains("if ($NoRun)"));
            assert!(script.contains("$request.AllowAutoRedirect = $false"));
            assert!(script.contains("if ($hop -eq 0) { $request.Headers['Authorization']"));
            let command = output
                .lines()
                .find(|line| line.starts_with("powershell "))
                .unwrap();
            assert!(command.len() <= 8191);
            assert!(command.contains("-File \"%TEMP%\\hostlink-bootstrap.ps1\""));
        } else {
            let download = output.rfind("\nhl_download ").unwrap();
            let digest = output.rfind("sha256sum -c -").unwrap();
            let prompt = output.rfind("One-use HostLink invite token:").unwrap();
            let install = output.rfind("\"$agent\" \"$@\"").unwrap();
            assert!(download < digest && digest < prompt && prompt < install);
            assert!(output.contains("root=\"$hl_data/hostlink/Agent\""));
            assert!(output.contains("$HOME/.local/share"));
            assert!(output.contains("set -- install --hub-url \"$hub_url\" --token-file \"$token_file\" --name \"$name\" --user \"$ssh_user\""));
            assert!(output.contains("curl -q -K -"));
            assert!(!output.contains("--location"));
            shell_syntax(&output);
        }
    }
}

#[test]
fn render_quotes_values_and_embeds_only_explicit_synthetic_credential() {
    let token = "github_pat_synthetic_fixture_123";
    for target in [
        Target::LinuxX64,
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ] {
        let mut selected = selection(target);
        selected.name = "lab'$(whoami)".into();
        selected.bootstrap_hub_ca_cert = Some(if target.windows() {
            r"C:\Users\Fixture User\сертификат's root.pem".into()
        } else {
            "/private/fixture ca.pem".into()
        });
        let normal = render_command(&selected);
        assert!(!normal.contains(token));
        let embedded = super::render::render_command_with_token(&selected, Some(token));
        if target.windows() {
            let script = windows_script(&embedded);
            assert!(windows_script(&normal).contains("\n[void](Get-GitHubCredential $true)\n"));
            assert!(script.contains("$Name='lab''$(whoami)'"));
            assert!(script.contains(r"$HubCaCert='C:\Users\Fixture User\сертификат''s root.pem'"));
            assert!(script.contains("'--hub-ca-cert', $HubCaCert"));
            assert!(script.contains(&format!("[void](Get-GitHubCredential $true '{token}')")));
            assert_eq!(embedded.matches(token).count(), 1);
            assert!(embedded.contains("WARNING: This helper contains your GitHub PAT"));
            assert!(!normal.contains("WARNING: This helper contains your GitHub PAT"));
            assert!(script.contains("SetAccessRuleProtection($true, $false)"));
            assert!(script.contains("Read-Host $Prompt -AsSecureString"));
        } else {
            assert!(embedded.contains("name='lab'\\''$(whoami)'"));
            assert!(embedded.contains("hub_ca_cert='/private/fixture ca.pem'"));
            assert!(embedded.contains("--hub-ca-cert \"$hub_ca_cert\""));
            assert!(normal.contains("\nhl_provision_credential\n"));
            assert!(embedded.contains(&format!("\nhl_provision_credential '{token}'\n")));
            assert!(embedded.contains("stty -echo </dev/tty"));
            assert!(!embedded.contains("--cacert"));
            shell_syntax(&embedded);
        }
    }
}

#[cfg(unix)]
fn shell_syntax(script: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-n")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

#[cfg(not(unix))]
fn shell_syntax(_script: &str) {}

#[tokio::test]
async fn metadata_download_is_bounded_and_unencoded() {
    use super::github::read_bounded;
    use axum::http::Response;
    let exact = reqwest::Response::from(Response::builder().body("1234").unwrap());
    assert_eq!(read_bounded(exact, 4).await.unwrap(), b"1234");
    for response in [
        Response::builder().body("12345").unwrap(),
        Response::builder()
            .header("content-length", "5")
            .body("")
            .unwrap(),
        Response::builder()
            .header("content-encoding", "gzip")
            .body("1234")
            .unwrap(),
    ] {
        assert!(
            read_bounded(reqwest::Response::from(response), 4)
                .await
                .is_err()
        );
    }
}

#[test]
fn gateway_index_is_only_forwarded_when_explicitly_selected() {
    for target in [Target::LinuxX64, Target::Win7X64] {
        let mut selected = selection(target);
        let default = render_command(&selected);
        selected.gateway_index = Some(0);
        let explicit = render_command(&selected);
        selected.gateway_index = Some(12);
        let other = render_command(&selected);
        if target.windows() {
            assert!(default.contains("$GatewayIndex=''"));
            assert!(explicit.contains("$GatewayIndex='0'"));
            assert!(other.contains("$GatewayIndex='12'"));
            assert!(explicit.contains("if (-not [string]::IsNullOrEmpty($GatewayIndex)) { $installArgs += @('--gateway-index', $GatewayIndex) }"));
        } else {
            assert!(default.contains("gateway_index=''"));
            assert!(explicit.contains("gateway_index='0'"));
            assert!(other.contains("gateway_index='12'"));
            assert!(explicit.contains("if [ -n \"$gateway_index\" ]; then set -- \"$@\" --gateway-index \"$gateway_index\"; fi"));
            shell_syntax(&explicit);
        }
    }
}
