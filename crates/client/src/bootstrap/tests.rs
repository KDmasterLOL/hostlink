use super::verify::validate_installer_bytes;
use super::*;
use reqwest::Url;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn installer_preflight_rejects_unsafe_ca_path_without_network_access() {
    let root = tempfile::tempdir().expect("private CA fixture");
    let huge = root.path().join("oversized-ca.pem");
    std::fs::write(&huge, vec![b'A'; 64 * 1024 + 1]).expect("oversized fixture");
    let selected = github_selection(Target::LinuxX64);
    let error = verify_installer(&selected, Some(&huge))
        .await
        .expect_err("oversized trust anchor must be rejected before HTTPS");
    assert!(error.to_string().contains("unsafe or invalid"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let linked = root.path().join("linked-ca.pem");
        symlink(&huge, &linked).expect("create hostile CA symlink");
        assert!(
            verify_installer(&selected, Some(&linked)).await.is_err(),
            "HTTPS trust root symlinks must not be followed"
        );
    }
}

fn github_selection(target: Target) -> ArtifactSelection {
    let asset = |id| {
        Url::parse(&format!(
            "https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/{id}"
        ))
        .unwrap()
    };
    ArtifactSelection {
        installer_url: asset(101),
        installer_sha256: "a".repeat(64),
        agent_url: asset(102),
        agent_sha256: "b".repeat(64),
        archive_url: asset(103),
        archive_sha256: "c".repeat(64),
        version: "1.2.3".into(),
        target,
        name: "lab-host".into(),
        ssh_user: "hostlink".into(),
        hub_url: "https://hub.example".into(),
        bootstrap_hub_ca_cert: None,
    }
}

fn rendered(selected: &ArtifactSelection) -> String {
    render_command(
        selected,
        &VerifiedInstaller {
            url: selected.installer_url.clone(),
            sha256: selected.installer_sha256.clone(),
        },
    )
}

#[test]
fn renders_target_credential_before_download_and_preserves_source_pins() {
    let mut linux = github_selection(Target::LinuxX64);
    linux.name = "lab'$(touch /tmp/pwned)".into();
    linux.bootstrap_hub_ca_cert = Some("/private/fixture ca.pem".into());
    let command = rendered(&linux);
    assert!(command.contains("'--name' 'lab'\\''$(touch /tmp/pwned)'"));
    assert!(command.contains("'--hub-ca-cert' '/private/fixture ca.pem'"));
    assert!(
        !command.contains("--cacert"),
        "Hub trust must not change GitHub trust"
    );
    assert!(command.contains("sha256sum -c -"));
    assert!(command.contains(&linux.installer_sha256));
    let provision = command.rfind("\nhl_provision_credential\n").unwrap();
    let download = command.rfind("\nhl_download '").unwrap();
    assert!(provision < download);
    assert!(command.contains("curl -q -K -"));
    assert!(
        command.contains("https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/101")
    );
    assert!(!command.contains("--invite-token"));
    // The generated body uses the exact same helper functions as the installer.
    let source = include_str!("../../../agent/assets/install-hostlink-agent.sh");
    let helpers = source
        .split_once("# BEGIN GITHUB BOOTSTRAP HELPERS\n")
        .unwrap()
        .1
        .split_once("# END GITHUB BOOTSTRAP HELPERS")
        .unwrap()
        .0;
    assert!(command.contains(helpers));
    #[cfg(unix)]
    {
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
            .write_all(command.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }
}

#[test]
fn windows_render_uses_explicit_two_step_helper_when_encoding_exceeds_cmd_limit() {
    for target in [Target::Win7X86, Target::Win7X64, Target::Win11X64] {
        let mut selected = github_selection(target);
        selected.name = "lab'$(whoami)".into();
        let output = rendered(&selected);
        let script = output
            .split_once("# BEGIN TARGET HELPER\n")
            .unwrap()
            .1
            .split_once("# END TARGET HELPER")
            .unwrap()
            .0;
        let encoded_len = 60 + 4 * (script.encode_utf16().count() * 2).div_ceil(3);
        assert!(encoded_len > 8191);
        let invocation = output
            .lines()
            .find(|line| line.starts_with("powershell "))
            .unwrap();
        assert!(invocation.len() <= 8191);
        assert!(invocation.contains("-File \"%USERPROFILE%\\hostlink-bootstrap.ps1\""));
        assert!(!output.contains("-EncodedCommand"));
        assert!(script.contains("-Name 'lab''$(whoami)'"));
        assert!(script.contains("$request.AllowAutoRedirect = $false"));
        assert!(script.contains("if ($hop -eq 0) { $request.Headers['Authorization']"));
        assert!(script.contains(&selected.installer_sha256));
        let provision = script.rfind("[void](Get-GitHubCredential $true)").unwrap();
        let download = script.rfind("$bytes=Get-GitHubAsset").unwrap();
        let digest = script.rfind("Installer SHA-256 mismatch").unwrap();
        let execute = script.rfind("& ([scriptblock]::Create($script))").unwrap();
        assert!(provision < download && download < digest && digest < execute);
        let source = include_str!("../../../agent/assets/Install-HostLink-Agent.ps1");
        let helpers = source
            .split_once("# BEGIN GITHUB BOOTSTRAP HELPERS\n")
            .unwrap()
            .1
            .split_once("# END GITHUB BOOTSTRAP HELPERS")
            .unwrap()
            .0;
        assert!(script.contains(helpers));
    }
}

#[test]
fn github_credential_is_embedded_only_by_explicit_render_opt_in() {
    // Synthetic fixture only: never use a real Controller credential in tests.
    let token = "github_pat_synthetic_fixture_123";
    for target in [
        Target::LinuxX64,
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ] {
        let selected = github_selection(target);
        let installer = VerifiedInstaller {
            url: selected.installer_url.clone(),
            sha256: selected.installer_sha256.clone(),
        };
        let normal = render_command(&selected, &installer);
        assert!(!normal.contains(token));
        let embedded = super::render::render_command_with_token(&selected, &installer, Some(token));
        if target.windows() {
            let script = embedded
                .split_once("# BEGIN TARGET HELPER\n")
                .expect("PowerShell 2 bootstrap must provide a local helper")
                .1
                .split_once("# END TARGET HELPER")
                .unwrap()
                .0;
            assert!(script.contains(&format!("[void](Get-GitHubCredential $true '{token}')")));
            assert!(embedded.contains("WARNING: This helper contains your GitHub PAT"));
            assert!(!normal.contains("WARNING: This helper contains your GitHub PAT"));
            assert!(script.contains("SetAccessRuleProtection($true, $false)"));
        } else {
            assert!(normal.contains("\nhl_provision_credential\n"));
            assert!(embedded.contains(&format!("\nhl_provision_credential '{token}'\n")));
            assert!(embedded.contains("sha256sum -c -"));
            #[cfg(unix)]
            {
                use std::io::Write;
                let mut shell = std::process::Command::new("/bin/sh")
                    .arg("-n")
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                shell
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(embedded.as_bytes())
                    .unwrap();
                assert!(shell.wait().unwrap().success());
            }
        }
    }
}

#[test]
fn installer_preflight_checks_digest_and_target_contract() {
    for (target, bytes) in [
        (
            Target::LinuxX64,
            include_bytes!("../../../agent/assets/install-hostlink-agent.sh").as_slice(),
        ),
        (
            Target::Win7X86,
            include_bytes!("../../../agent/assets/Install-HostLink-Agent.ps1").as_slice(),
        ),
    ] {
        let digest = format!("{:x}", Sha256::digest(bytes));
        assert!(validate_installer_bytes(bytes, &digest, target).is_ok());
        assert!(validate_installer_bytes(bytes, &"0".repeat(64), target).is_err());
    }
    let bytes = b"unrelated script";
    assert!(
        validate_installer_bytes(
            bytes,
            &format!("{:x}", Sha256::digest(bytes)),
            Target::LinuxX64
        )
        .is_err()
    );
}

#[test]
fn selection_requires_fixed_private_api_distinct_assets_and_all_pins() {
    for target in [
        Target::LinuxX64,
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
    ] {
        let mut selected = github_selection(target);
        assert_eq!(Target::parse(target.as_str()).unwrap(), target);
        selected.validate().unwrap();
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
            selected.installer_url = Url::parse(url).unwrap();
            assert!(selected.validate().is_err(), "{url}");
        }
        selected.installer_url = selected.agent_url.clone();
        assert!(selected.validate().is_err());
    }
    for index in 0..3 {
        let mut selected = github_selection(Target::LinuxX64);
        [
            &mut selected.installer_sha256,
            &mut selected.agent_sha256,
            &mut selected.archive_sha256,
        ][index]
            .clear();
        assert!(selected.validate().is_err());
    }
    assert!(Target::parse("automatic").is_err());
}

#[test]
fn redirect_allows_one_approved_cdn_request_without_authorization() {
    use super::verify::installer_redirect;
    use axum::http::Response;
    let client = super::github::github_client().unwrap();
    let redirect = |location: &str| {
        reqwest::Response::from(
            Response::builder()
                .status(302)
                .header("location", location)
                .body("")
                .unwrap(),
        )
    };
    for host in [
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    ] {
        let response = redirect(&format!("https://{host}/asset?signed=synthetic"));
        let request = installer_redirect(&client, &response)
            .unwrap()
            .unwrap()
            .build()
            .unwrap();
        assert!(
            !request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );
        // The download path requires 200 after this one hop.
        assert!(super::github::require_ok(response.status()).is_err());
    }
    for location in [
        "https://elsewhere.invalid/a",
        "https://user@objects.githubusercontent.com/a",
        "http://objects.githubusercontent.com/a",
        "https://objects.githubusercontent.com:444/a",
        "https://objects.githubusercontent.com/a#frag",
    ] {
        assert!(installer_redirect(&client, &redirect(location)).is_err());
    }
    for status in [200, 301, 302, 307, 401] {
        let response =
            reqwest::Response::from(Response::builder().status(status).body("").unwrap());
        assert_eq!(
            installer_redirect(&client, &response).is_ok(),
            status == 200
        );
    }
    let ambiguous = reqwest::Response::from(
        Response::builder()
            .status(302)
            .header("location", "https://objects.githubusercontent.com/a")
            .header("location", "https://objects.githubusercontent.com/b")
            .body("")
            .unwrap(),
    );
    assert!(installer_redirect(&client, &ambiguous).is_err());
}

#[tokio::test]
async fn download_checks_declared_and_actual_size_and_encoding() {
    use super::verify::read_bounded;
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
