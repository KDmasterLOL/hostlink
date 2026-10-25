use hostlink::migration::{self, Readiness};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

struct Inputs {
    root: TempDir,
    hub: PathBuf,
    controller: PathBuf,
    old_agent: PathBuf,
    new_agent: PathBuf,
    new_host: PathBuf,
}

impl Inputs {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path();
        let key = root_path.join("id_ed25519");
        let host_key = root_path.join("agent_host_key");
        let gateway_key = root_path.join("gateway_host_key");
        let authorized = root_path.join("authorized_keys");
        let jobs = root_path.join("jobs");
        for path in [&key, &host_key, &gateway_key, &authorized] {
            fs::write(path, b"fixture key material").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fs::create_dir(&jobs).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let hub = root_path.join("old-hub.json");
        let controller = root_path.join("old-controller.json");
        let old_agent = root_path.join("old-agent.json");
        let new_agent = root_path.join("new-agent.json");
        let new_host = root_path.join("new-host.json");
        write(
            &hub,
            json!({
                "version": 1,
            "gateways": [{"host":"gateway.example.test", "user":"agent", "port":22, "host_public_key":pin()}],
                "operator_token_env":"LEGACY_TOKEN_CANARY"
            }),
        );
        write(
            &controller,
            json!({
                "version": 1,
                "gateways": [{"host":"gateway.example.test", "user":"operator", "port":22}],
                "identity": key,
                "known_hosts": "known_hosts",
                "token_env": "OLD_HUB_API_TOKEN"
            }),
        );
        write(
            &old_agent,
            json!({
                "version": 1,
                "name":"agent-name-is-not-reported",
                "jobs_dir":"C:/old/jobs",
                "ssh": {
                    "gateways": [{"host":"gateway.example.test", "user":"agent", "port":22}],
                    "remote_port":41000,
                    "identity":"old-id",
                    "known_hosts":"old-known-hosts"
                }
            }),
        );
        write(
            &new_agent,
            json!({
                "listen":"127.0.0.1:32000",
                "user":"agent",
                "host_key":host_key,
                "authorized_keys":authorized,
                "jobs_root":jobs,
                "gateway": {
                    "host":"gateway.example.test",
                    "port":22,
                    "user":"agent",
                    "identity":key,
                    "host_public_key":gateway_key,
                    "remote_port":41000
                }
            }),
        );
        write(
            &new_host,
            json!({
                "endpoint":"127.0.0.1:41000",
                "user":"agent",
                "identity":key,
                "host_public_key":pin(),
                "gateway": {
                    "address":"127.0.0.1:22",
                    "user":"agent",
                    "identity":key,
                    "host_public_key":pin(),
                    "reverse_port":41000
                }
            }),
        );
        Self {
            root,
            hub,
            controller,
            old_agent,
            new_agent,
            new_host,
        }
    }

    fn report(&self) -> migration::MigrationReport {
        migration::preflight(
            &self.hub,
            &self.controller,
            &self.old_agent,
            &self.new_agent,
            &self.new_host,
        )
        .unwrap()
    }
}

fn write(path: &Path, value: Value) {
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn pin() -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut blob = Vec::new();
    blob.extend_from_slice(&11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(&[7; 32]);
    format!("ssh-ed25519 {} fixture", STANDARD.encode(blob))
}

#[test]
fn exact_single_gateway_pair_is_review_ready_and_redacted_without_writes() {
    let input = Inputs::new();
    let before = fs::read(&input.new_agent).unwrap();
    let report = input.report();
    assert_eq!(report.hosts[0].readiness, Readiness::Review);
    assert!(
        report.hosts[0].blockers.is_empty(),
        "{:?}",
        report.hosts[0].blockers
    );
    assert_eq!(report.hosts[0].host, "host-001");
    assert!(!report.writes_performed);
    assert!(!report.network_attempted);
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("LEGACY_TOKEN_CANARY"));
    assert!(!rendered.contains("OLD_HUB_API_TOKEN"));
    assert!(!rendered.contains("agent-name-is-not-reported"));
    assert_eq!(fs::read(&input.new_agent).unwrap(), before);
    assert_eq!(input.root.path().read_dir().unwrap().count(), 10);

    let output = Command::new(env!("CARGO_BIN_EXE_hostlink"))
        .args([
            "migration",
            "preflight",
            "--old-hub",
            input.hub.to_str().unwrap(),
            "--old-controller",
            input.controller.to_str().unwrap(),
            "--old-agent",
            input.old_agent.to_str().unwrap(),
            "--new-agent",
            input.new_agent.to_str().unwrap(),
            "--new-host",
            input.new_host.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let cli_report = String::from_utf8(output.stdout).unwrap();
    assert!(cli_report.contains("\"network_attempted\": false"));
    assert!(!cli_report.contains("LEGACY_TOKEN_CANARY"));
    assert!(!cli_report.contains("agent-name-is-not-reported"));
}

#[test]
fn legacy_hub_single_gateway_fields_are_read_without_defaults() {
    let input = Inputs::new();
    let mut hub: Value = serde_json::from_slice(&fs::read(&input.hub).unwrap()).unwrap();
    hub["gateways"] = json!([]);
    hub["gateway_host"] = json!("gateway.example.test");
    hub["agent_ssh_user"] = json!("agent");
    hub["gateway_ssh_port"] = json!(22);
    hub["gateway_host_public_key"] = json!(pin());
    write(&input.hub, hub);
    let report = input.report();
    assert!(
        report.hosts[0].blockers.is_empty(),
        "{:?}",
        report.hosts[0].blockers
    );
    assert_eq!(report.hosts[0].readiness, Readiness::Review);
}

#[test]
fn unknown_and_multiple_routes_fail_closed() {
    let input = Inputs::new();
    let mut old_agent: Value =
        serde_json::from_slice(&fs::read(&input.old_agent).unwrap()).unwrap();
    old_agent["ssh"]["gateways"] = json!([
        {"host":"unknown.example.test", "user":"agent", "port":22}
    ]);
    write(&input.old_agent, old_agent.clone());
    let unknown_report = input.report();
    assert_eq!(unknown_report.hosts[0].readiness, Readiness::Blocked);
    assert!(
        unknown_report.hosts[0]
            .blockers
            .iter()
            .any(|v| v.contains("does not match the Hub gateway"))
    );

    old_agent["ssh"]["gateways"] = json!([
        {"host":"gateway.example.test", "user":"agent", "port":22},
        {"host":"other.example.test", "user":"agent", "port":2222}
    ]);
    write(&input.old_agent, old_agent);
    let report = input.report();
    assert_eq!(report.hosts[0].readiness, Readiness::Blocked);
    assert!(
        report.hosts[0]
            .blockers
            .iter()
            .any(|v| v.contains("multiple legacy gateways"))
    );
}

#[test]
fn tls_proxy_duplicate_ports_missing_pins_and_secret_auth_are_blockers() {
    let input = Inputs::new();
    let mut agent: Value = serde_json::from_slice(&fs::read(&input.old_agent).unwrap()).unwrap();
    agent["ssh"]["tls_proxy"] = json!({"program":"proxy", "server_name":"gateway.example.test"});
    write(&input.old_agent, agent);
    let mut hub: Value = serde_json::from_slice(&fs::read(&input.hub).unwrap()).unwrap();
    hub["gateways"] = json!([
        {"host":"gateway.example.test", "user":"agent", "port":22, "host_public_key":pin()},
        {"host":"second.example.test", "user":"agent", "port":22, "host_public_key":pin()}
    ]);
    write(&input.hub, hub);
    let mut host: Value = serde_json::from_slice(&fs::read(&input.new_host).unwrap()).unwrap();
    host.as_object_mut().unwrap().remove("host_public_key");
    write(&input.new_host, host);
    let mut controller: Value =
        serde_json::from_slice(&fs::read(&input.controller).unwrap()).unwrap();
    controller["identity"] = json!(
        controller["token_file"]
            .as_str()
            .unwrap_or("OLD_HUB_API_TOKEN")
    );
    controller["token_file"] = json!("OLD_HUB_API_TOKEN");
    write(&input.controller, controller);
    let report = input.report();
    assert_eq!(report.hosts[0].readiness, Readiness::Blocked);
    let blockers = report.hosts[0].blockers.join(" ");
    assert!(blockers.contains("TLS proxy"));
    assert!(blockers.contains("reuse a port"));
    assert!(blockers.contains("host pin"));
    assert!(blockers.contains("not an SSH authentication credential"));
    assert!(!blockers.contains("OLD_HUB_API_TOKEN"));
}

#[cfg(unix)]
#[test]
fn symlinked_snapshot_is_rejected_without_echoing_contents() {
    use std::os::unix::fs::symlink;
    let input = Inputs::new();
    let link = input.root.path().join("old-hub-link.json");
    symlink(&input.hub, &link).unwrap();
    let error = migration::preflight(
        &link,
        &input.controller,
        &input.old_agent,
        &input.new_agent,
        &input.new_host,
    )
    .unwrap_err();
    assert_eq!(
        error,
        "supplied snapshots must be bounded regular files, not symlinks"
    );
    assert!(!error.contains("LEGACY_TOKEN_CANARY"));
}

#[cfg(unix)]
#[test]
fn symlinked_desired_process_root_is_a_blocker() {
    use std::os::unix::fs::symlink;
    let input = Inputs::new();
    let unsafe_root = input.root.path().join("process-root-link");
    symlink(input.root.path().join("jobs"), &unsafe_root).unwrap();
    let mut agent: Value = serde_json::from_slice(&fs::read(&input.new_agent).unwrap()).unwrap();
    agent["jobs_root"] = json!(unsafe_root);
    write(&input.new_agent, agent);
    let report = input.report();
    assert_eq!(report.hosts[0].readiness, Readiness::Blocked);
    assert!(
        report.hosts[0]
            .blockers
            .iter()
            .any(|v| v.contains("traverses a symlink"))
    );
}
