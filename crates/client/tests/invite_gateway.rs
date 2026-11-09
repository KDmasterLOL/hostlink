#![cfg(unix)]

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::read::GzDecoder;
use russh::keys::{Algorithm, PrivateKey};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
};

const SERVER: &str = include_str!("fixtures/invite_hub.py");

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unpack(command: &str, windows: bool) -> String {
    let marker = if windows {
        "FromBase64String('"
    } else {
        "printf %s '"
    };
    let encoded = command
        .split(marker)
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    let bytes = STANDARD.decode(encoded).unwrap();
    let mut script = String::new();
    GzDecoder::new(bytes.as_slice())
        .read_to_string(&mut script)
        .unwrap();
    script
}

#[test]
fn invalid_gateway_selection_never_creates_an_invite() {
    exercise_invites(false);
}

#[test]
#[ignore = "requires public GitHub v0.1.1 release metadata"]
fn invite_embeds_authenticated_selected_route() {
    exercise_invites(true);
}

fn exercise_invites(online: bool) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let cert = root.path().join("cert.pem");
    let key = root.path().join("key.pem");
    assert!(
        Command::new("openssl")
            .args("req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=IP:127.0.0.1 -addext basicConstraints=critical,CA:FALSE -keyout".split_whitespace())
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let token = root.path().join("token");
    fs::write(&token, "fixture-operator-token").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let routes: Vec<_> = ["edge-a.example", "edge-b.example"]
        .iter()
        .map(|host| {
            let pin = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap();
            serde_json::json!({"host": host, "port": 22, "user": "gateway", "host_public_key": pin})
        })
        .collect();
    let mut child = Command::new("python3")
        .arg("-u")
        .arg("-c")
        .arg(SERVER)
        .arg(root.path())
        .arg(&cert)
        .arg(&key)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut port = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    let _server = Server(child);
    let config = root.path().join("hub.json");
    let requests = root.path().join("requests");
    for (count, preferred, explicit, os, user, expected) in [
        (2, Some("edge-b.example:22"), None, "windows", None, Some(1)),
        (1, None, None, "linux", None, Some(0)),
        (
            2,
            Some("edge-b.example:22"),
            Some("0"),
            "linux",
            Some("hostlink"),
            Some(0),
        ),
        (1, None, None, "windows", Some("hostlink"), Some(0)),
        (2, None, None, "token", None, None),
        (2, None, None, "token", Some("other"), None),
        (2, None, None, "windows", Some("other"), None),
        (2, None, None, "linux", Some("other"), None),
        (2, None, Some("2"), "linux", None, None),
        (2, None, None, "linux", None, None),
        (2, Some("stale.example:22"), None, "linux", None, None),
        (0, None, None, "linux", None, None),
    ] {
        if expected.is_some() != online {
            continue;
        }
        fs::write(root.path().join("info.json"), serde_json::to_vec(&serde_json::json!({"api_version":2,"management":true,"gateways":&routes[..count],"execution_transport":"russh","hosts_endpoint":"/v2/hosts"})).unwrap()).unwrap();
        fs::write(&config, serde_json::to_vec(&serde_json::json!({"hub_url":format!("https://127.0.0.1:{}", port.trim()),"hub_ca_cert":cert,"token_file":token,"ssh_user":"hostlink","identity":"unused","gateway_identity":"unused","preferred_gateway":preferred})).unwrap()).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&requests, "").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_hostlink"));
        command
            .args(["invite", "lab-host"])
            .env("HOSTLINK_HUB_CONFIG", &config)
            .env("HOME", root.path());
        if os == "token" {
            command.arg("--token-only");
        } else {
            command.args(["--os", os, "--version", "0.1.1"]);
        }
        if let Some(index) = explicit {
            command.args(["--gateway-index", index]);
        }
        if let Some(user) = user {
            command.args(["--ssh-user", user]);
        }
        let output = command.output().unwrap();
        let log = fs::read_to_string(&requests).unwrap();
        if user == Some("other") {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(log.is_empty(), "unexpected Hub requests: {log}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            if os == "token" {
                assert!(stderr.contains("cannot be used with"), "{stderr}");
            } else {
                assert!(stderr.contains("--ssh-user must match"), "{stderr}");
            }
        } else if os == "token" {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(log, "POST /v2/invites\n");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(&format!("token: {}", "a".repeat(64))));
            assert!(text.contains("artifact_binding: token-only; no bootstrap command"));
        } else if let Some(index) = expected {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(log, "GET /v2/info\nGET /v2/hosts\nPOST /v2/invites\n");
            let cmd = String::from_utf8(output.stdout).unwrap();
            let cmd = cmd.trim_end();
            assert!(!cmd.contains('\n'));
            if os == "windows" {
                assert!(cmd.len() <= 8191);
            }
            let script = unpack(cmd, os == "windows");
            let user_assignment = if os == "windows" {
                "$SshUser='hostlink'"
            } else {
                "ssh_user='hostlink'"
            };
            assert!(script.lines().any(|line| line == user_assignment));
            let assignment = if os == "windows" {
                format!("$GatewayIndex='{index}'")
            } else {
                format!("gateway_index='{index}'")
            };
            assert!(script.lines().any(|line| line == assignment));
            if os == "linux" {
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
        } else {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert_eq!(log, "GET /v2/info\n");
            let stderr = String::from_utf8_lossy(&output.stderr);
            let guidance = if count == 0 {
                "no approved gateway"
            } else {
                "--gateway-index"
            };
            assert!(stderr.contains(guidance), "{stderr}");
        }
    }
}
