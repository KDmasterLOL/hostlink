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

// The fixture serves actual authenticated HTTPS; GitHub metadata remains the production source.
const SERVER: &str = r#"
import http.server, json, ssl, sys
root, cert, key = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def handle_request(self):
        with open(root + '/requests', 'a') as f: f.write(self.command + ' ' + self.path + '\n')
        if self.headers.get('Authorization') != 'Bearer fixture-operator-token':
            self.send_error(401); return
        if self.command == 'GET' and self.path == '/v2/info':
            with open(root + '/info.json') as f: body = json.load(f)
        elif self.command == 'POST' and self.path == '/v2/invites':
            self.rfile.read(int(self.headers['Content-Length']))
            body = {'token': 'a' * 64, 'expires_at': 4102444800}
        else:
            self.send_error(404); return
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)
    do_GET = handle_request
    do_POST = handle_request
server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
"#;

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
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout"
            ])
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
    for (count, preferred, explicit, os, expected) in [
        (2, Some("edge-b.example:22"), None, "windows", Some(1)),
        (1, None, None, "linux", Some(0)),
        (2, Some("edge-b.example:22"), Some("0"), "linux", Some(0)),
        (2, None, Some("2"), "linux", None),
        (2, None, None, "linux", None),
        (2, Some("stale.example:22"), None, "linux", None),
        (0, None, None, "linux", None),
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
            .args(["invite", "lab-host", "--os", os, "--version", "0.1.1"])
            .env("HOSTLINK_HUB_CONFIG", &config)
            .env("HOME", root.path());
        if let Some(index) = explicit {
            command.args(["--gateway-index", index]);
        }
        let output = command.output().unwrap();
        let log = fs::read_to_string(&requests).unwrap();
        if let Some(index) = expected {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(log, "GET /v2/info\nPOST /v2/invites\n");
            let cmd = String::from_utf8(output.stdout).unwrap();
            let cmd = cmd.trim_end();
            assert!(!cmd.contains('\n'));
            if os == "windows" {
                assert!(cmd.len() <= 8191);
            }
            let script = unpack(cmd, os == "windows");
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
