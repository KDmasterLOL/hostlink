use super::*;
use reqwest::Url;

fn selection(target: Target) -> ArtifactSelection {
    ArtifactSelection {
        agent_url: Url::parse(
            "https://github.com/KDmasterLOL/hostlink/releases/download/v1.2.3/hostlink-agent-x86_64-unknown-linux-gnu",
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

#[cfg(unix)]
#[test]
fn public_download_follows_one_redirect_and_parses_curl_newline() {
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
if [ ! -e "$HL_COUNT" ]; then
    : > "$HL_COUNT"
    printf '302\nhttps://release-assets.githubusercontent.com/synthetic'
else
    printf binary > "$out"
    printf '200\n'
fi
"##,
    )
    .unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o700)).unwrap();
    let dest = dir.path().join("agent");
    let script = format!(
        "{}\nhl_download 'https://github.com/KDmasterLOL/hostlink/releases/download/v0.1.0/hostlink-agent-test' \"$HL_DEST\" 1024 10",
        include_str!("../../../assets/github-posix.sh")
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("HL_COUNT", dir.path().join("count"))
        .env("HL_DEST", &dest)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(dest).unwrap(), b"binary");
}

#[cfg(unix)]
#[test]
fn wrong_digest_never_executes_downloaded_binary() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let curl = dir.path().join("curl");
    fs::write(
        &curl,
        r##"#!/bin/sh
if [ "$2" = --version ]; then echo 'curl 8.4.0'; exit; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then shift; out=$1; fi
  shift
done
printf '#!/bin/sh\ntouch "$HL_MARKER"\n' > "$out"
printf '200\n'
"##,
    )
    .unwrap();
    fs::set_permissions(curl, fs::Permissions::from_mode(0o700)).unwrap();
    let script = format!(
        "set -eu\n{}\nagent_url='https://github.com/KDmasterLOL/hostlink/releases/download/v0.1.0/hostlink-agent-test'\nagent_sha256='{}'\nhub_url=https://example.invalid\nname=test\nssh_user=test\nhub_ca_cert=''\ngateway_index=''\nHL_INVITE=synthetic\n{}",
        include_str!("../../../assets/github-posix.sh"),
        "0".repeat(64),
        include_str!("../../../assets/bootstrap-posix.sh")
    );
    let marker = dir.path().join("executed");
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("HOME", dir.path())
        .env("TMPDIR", dir.path())
        .env("HL_MARKER", &marker)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("FAILED"));
    assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("hostlink-bootstrap.")
    }));
}
