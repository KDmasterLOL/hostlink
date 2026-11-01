use super::*;

#[tokio::test]
async fn installer_preflight_rejects_unsafe_ca_path_without_network_access() {
    let root = tempfile::tempdir().expect("private CA fixture");
    let huge = root.path().join("oversized-ca.pem");
    std::fs::write(&huge, vec![b'A'; 64 * 1024 + 1]).expect("oversized fixture");
    let selected = selection(Target::LinuxX64);
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

fn selection(target: Target) -> ArtifactSelection {
    let agent = if target.windows() {
        "hostlink-agent.exe"
    } else {
        "hostlink-agent"
    };
    ArtifactSelection {
        installer_url: Url::parse("https://artifacts.example/install.sh?immutable=1").unwrap(),
        installer_sha256: "a".repeat(64),
        agent_url: Url::parse(&format!(
            "https://artifacts.example/v1.2.3/{}/{agent}",
            target.as_str()
        ))
        .unwrap(),
        agent_sha256: "b".repeat(64),
        archive_url: Url::parse(&format!(
            "https://artifacts.example/v1.2.3/hostlink-agent-{}.zip",
            target.as_str()
        ))
        .unwrap(),
        archive_sha256: "c".repeat(64),
        version: "1.2.3".into(),
        target,
        name: "lab-host".into(),
        ssh_user: "hostlink".into(),
        hub_url: "https://hub.example".into(),
        bootstrap_hub_ca_cert: None,
    }
}

#[test]
fn supports_only_the_four_installer_targets_and_matching_archive_names() {
    for target in [
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
        Target::LinuxX64,
    ] {
        assert!(selection(target).validate().is_ok());
    }
    assert!(Target::parse("x86_64-unknown-linux-musl").is_err());
    let mut wrong = selection(Target::Win7X86);
    wrong.archive_url =
        Url::parse("https://artifacts.example/v9.9.9/hostlink-agent-x86_64-win7-windows-msvc.zip")
            .unwrap();
    assert!(wrong.validate().is_err());
}

#[test]
fn rejects_missing_or_swapped_source_pins_and_unsafe_urls_before_request() {
    let mut missing = selection(Target::LinuxX64);
    missing.installer_sha256.clear();
    assert!(missing.validate().is_err());
    let mut swapped = selection(Target::LinuxX64);
    swapped.archive_url =
        Url::parse("https://other.example/v1.2.3/hostlink-agent-x86_64-unknown-linux-gnu.zip")
            .unwrap();
    assert!(swapped.validate().is_err());
    assert!(https_url("https://[malformed").is_err());
    for url in [
        "http://artifacts.example/i.sh",
        "https://user@artifacts.example/i.sh",
        "https://@artifacts.example/i.sh",
        "https://artifacts.example/i.sh#frag",
        "https://artifacts.example/a/%2e%2e/i.sh",
        "https://artifacts.example/a/%2f../i.sh",
        "https://artifacts.example/a/%252e%252e/i.sh",
    ] {
        assert!(parse_artifact_url(url).is_err(), "{url}");
    }
}

#[test]
fn renders_powershell_and_posix_commands_with_quoted_arguments_and_no_token() {
    let mut windows = selection(Target::Win7X64);
    windows.installer_url = Url::parse("https://artifacts.example/i'$(whoami).ps1").unwrap();
    let command = render_command(
        &windows,
        &VerifiedInstaller {
            url: windows.installer_url.clone(),
            sha256: windows.installer_sha256.clone(),
        },
    );
    assert!(command.starts_with("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand "));
    let encoded = command.split_whitespace().last().unwrap();
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
    let (pairs, remainder) = decoded.as_chunks::<2>();
    assert!(remainder.is_empty());
    let words = pairs
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    let script = String::from_utf16(&words).unwrap();
    assert!(script.contains("New-Object Uri('https://artifacts.example/i''$(whoami).ps1')"));
    assert!(script.contains("-Name 'lab-host'"));
    assert!(script.contains("$r.AllowAutoRedirect=$false"));
    assert!(script.contains(&windows.installer_sha256));
    assert!(!command.contains("invite-token"));

    let mut linux = selection(Target::LinuxX64);
    linux.installer_url =
        Url::parse("https://artifacts.example/i'$(touch%20/tmp/pwned).sh").unwrap();
    linux.bootstrap_hub_ca_cert = Some("/private/fixture ca.pem".into());
    let command = render_command(
        &linux,
        &VerifiedInstaller {
            url: linux.installer_url.clone(),
            sha256: linux.installer_sha256.clone(),
        },
    );
    assert!(command.contains("'--name' 'lab-host'"));
    assert!(command.contains("'https://artifacts.example/i'\\''$(touch%20/tmp/pwned).sh'"));
    assert!(command.contains("--cacert '/private/fixture ca.pem'"));
    assert!(command.contains("'--hub-ca-cert' '/private/fixture ca.pem'"));
    assert!(command.contains("sha256sum -c -"));
    assert!(!command.contains("token"));
}

#[test]
fn installer_contract_is_platform_specific_and_version_is_exact_semver() {
    assert!(semver("1.2.3-rc.1+build.4"));
    assert!(!semver("1.2.3-"));
    assert!(!semver("01.2.3"));
    assert!(!semver("latest"));
    assert!(!semver("18446744073709551616.0.0"));
    assert!(!semver("1.2.3-01"));
    assert!(semver("0.0.0+sha.aa11"));
    assert!(validate_installer_contract("HubUrl Name SshUser AgentUri AgentSha256 ArchiveUri ArchiveSha256 AgentVersion Target Read-Host -AsSecureString", Target::Win11X64).is_ok());
    assert!(validate_installer_contract("--hub-url --name --ssh-user --agent-url --agent-sha256 --archive-url --archive-sha256 --agent-version --target stty -echo", Target::LinuxX64).is_ok());
    assert!(validate_installer_contract("--hub-url --name", Target::LinuxX64).is_err());
    assert!(
        validate_installer_contract(
            include_str!("../../../agent/assets/Install-HostLink-Agent.ps1"),
            Target::Win7X86
        )
        .is_ok()
    );
    assert!(
        validate_installer_contract(
            include_str!("../../../agent/assets/install-hostlink-agent.sh"),
            Target::LinuxX64
        )
        .is_ok()
    );
    let source = "--hub-url --name --ssh-user --agent-url --agent-sha256 --archive-url --archive-sha256 --agent-version --target stty -echo";
    let source_sha256 = format!("{:x}", Sha256::digest(source.as_bytes()));
    assert!(validate_installer_bytes(source.as_bytes(), &source_sha256, Target::LinuxX64).is_ok());
    assert!(
        validate_installer_bytes(source.as_bytes(), &"0".repeat(64), Target::LinuxX64).is_err()
    );
}

#[tokio::test]
async fn local_disposable_http_fixture_rejects_redirects_and_accepts_exact_bytes() {
    async fn serve(response: &'static str) -> Option<String> {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP local HTTP fixture: sandbox denied loopback bind: {error}");
                return None;
            }
            Err(error) => panic!("bind disposable HTTP fixture: {error}"),
        };
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                .await
                .unwrap();
        });
        Some(format!("http://{address}/installer"))
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let valid = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest";
    let Some(valid_url) = serve(valid).await else {
        return;
    };
    let bytes = fetch_bytes(&client, Url::parse(&valid_url).unwrap())
        .await
        .unwrap();
    assert_eq!(bytes, b"test");
    let redirect = "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/script\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let Some(redirect_url) = serve(redirect).await else {
        return;
    };
    let error = fetch_bytes(&client, Url::parse(&redirect_url).unwrap())
        .await
        .unwrap_err();
    assert!(error.contains("without redirects"));
}
