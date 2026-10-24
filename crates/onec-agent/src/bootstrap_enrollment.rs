//! Build fresh user-scope Agent state from one authoritative Hub enrollment response.

use crate::AgentConfig;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "agent.json";
const TOKEN_REQUEST_FILE: &str = ".enrollment-request.json";
const HUB_RESPONSE_FILE: &str = ".enrollment-response.json";
const LOGICAL_SSH_USER: &str = "hostlink";

/// Inputs for one non-retriable fresh enrollment attempt.
#[derive(Debug)]
pub struct PrepareEnrollmentRequest {
    /// Hub origin or the exact `/v1/enroll` HTTPS endpoint.
    pub hub_url: String,
    /// Absolute private file containing the one-use bearer token.
    pub token_file: PathBuf,
    /// New absolute private directory where the candidate state is assembled.
    pub state_dir: PathBuf,
    /// Optional canonical requested Hub label.
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    machine_id: &'a str,
    name: &'a str,
    hostname: &'a str,
    username: Option<&'a str>,
    os: &'a str,
    arch: &'a str,
    agent_version: &'a str,
    transport: &'static str,
    persistence_mode: &'static str,
    ssh_public_key: String,
    ssh_host_public_key: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    machine_id: String,
    name: String,
    control_secret: String,
    remote_port: u16,
    gateways: Vec<Gateway>,
    #[serde(default)]
    operator_ssh_public_keys: Option<Vec<String>>,
    #[serde(default)]
    operator_ssh_public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Gateway {
    host: String,
    user: String,
    port: u16,
    host_public_key: String,
}

#[derive(Debug)]
struct ValidatedHubResponse {
    machine_id: String,
    name: String,
    control_secret: String,
    remote_port: u16,
    gateways: Vec<GatewayEndpointDocument>,
    known_hosts: String,
    authorized_keys: String,
}

#[derive(Debug, Serialize)]
struct AgentConfigDocument {
    version: u32,
    name: String,
    listen: &'static str,
    secret_env: &'static str,
    secret_file: &'static str,
    jobs_dir: &'static str,
    ssh: SshConfigDocument,
    embedded_ssh_server: EmbeddedSshDocument,
}

#[derive(Debug, Serialize)]
struct SshConfigDocument {
    gateways: Vec<GatewayEndpointDocument>,
    remote_port: u16,
    identity: &'static str,
    known_hosts: &'static str,
    reconnect_seconds: u64,
}

#[derive(Debug, Serialize)]
struct GatewayEndpointDocument {
    host: String,
    user: String,
    port: u16,
}

#[derive(Debug, Serialize)]
struct EmbeddedSshDocument {
    user: &'static str,
    host_key: &'static str,
    authorized_keys: &'static str,
    port: u16,
}

/// Perform one Hub enrollment and write a complete, validated fresh Agent config.
///
/// The bearer token is read by the existing HTTPS-only transport. This function never retries:
/// after a transport or response failure, the token outcome can be uncertain and a new invite is
/// required.
///
/// # Errors
///
/// Returns an I/O error for unsafe paths, invalid Hub data, enrollment failure, or failed config
/// validation/publication.
pub fn prepare_enrollment(request: PrepareEnrollmentRequest) -> io::Result<()> {
    if !request.state_dir.is_absolute() || !request.token_file.is_absolute() {
        return Err(invalid("state-dir and token-file must be absolute paths"));
    }
    if let Some(name) = request.name.as_deref() {
        validate_identifier(name, "name")?;
    }
    hostlink_core::create_private_directory(&request.state_dir)?;
    let state = &request.state_dir;
    let (outbound_key, outbound_public) = generate_ed25519_keypair()?;
    let (server_key, server_public) = generate_ed25519_keypair()?;
    if outbound_public == server_public {
        return Err(invalid("independent SSH identities unexpectedly collided"));
    }

    let machine_id = uuid::Uuid::new_v4().to_string().to_ascii_lowercase();
    let hostname = local_hostname()?;
    let default_name = canonical_label(&hostname);
    let default_name = if default_name.is_empty() {
        format!("host-{}", &machine_id[..8])
    } else {
        default_name
    };
    let requested_name = request.name.as_deref().unwrap_or(&default_name);
    validate_identifier(requested_name, "name")?;
    let enroll = EnrollRequest {
        machine_id: &machine_id,
        name: requested_name,
        hostname: &hostname,
        username: Some(LOGICAL_SSH_USER),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        agent_version: env!("CARGO_PKG_VERSION"),
        transport: "open_ssh",
        persistence_mode: "user-session",
        ssh_public_key: outbound_public,
        ssh_host_public_key: server_public,
    };
    let body_path = state.join(TOKEN_REQUEST_FILE);
    let response_path = state.join(HUB_RESPONSE_FILE);
    let body = serde_json::to_vec(&enroll).map_err(io::Error::other)?;
    hostlink_core::write_new_private_bytes(&body_path, &body)?;
    let enrollment_url = endpoint_url(&request.hub_url)?;
    let post_result = crate::post_enrollment_json(
        &enrollment_url,
        &request.token_file,
        &body_path,
        &response_path,
    );
    let _ = std::fs::remove_file(&body_path);
    post_result.map_err(one_use_reconciliation_error)?;

    let response = read_validate_and_remove_response(&response_path, &machine_id)?;
    write_enrolled_state_or_cleanup(state, response, &outbound_key, &server_key)
        .map_err(one_use_reconciliation_error)
}

fn one_use_reconciliation_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "Hub may have consumed this one-use invite; do not retry it; create a new invite and reconcile the Hub record: {error}"
        ),
    )
}

fn read_validate_and_remove_response(
    response_path: &Path,
    expected_machine_id: &str,
) -> io::Result<ValidatedHubResponse> {
    let response_result = (|| {
        let response_bytes = hostlink_core::read_file_bounded(response_path, 1024 * 1024)?;
        let response: EnrollmentResponse =
            serde_json::from_slice(&response_bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Hub enrollment response: {error}"),
                )
            })?;
        validate_hub_response(response, expected_machine_id)
    })();
    let cleanup_result = std::fs::remove_file(response_path);
    let response = response_result.map_err(one_use_reconciliation_error)?;
    cleanup_result.map_err(one_use_reconciliation_error)?;
    Ok(response)
}

fn generate_ed25519_keypair() -> io::Result<(String, String)> {
    let private = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let public = normalize_ed25519(
        &private
            .public_key()
            .to_openssh()
            .map_err(io::Error::other)?,
    )?;
    let private_text = private
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(io::Error::other)?;
    Ok((private_text.to_string(), public))
}

fn normalize_ed25519(value: &str) -> io::Result<String> {
    let key = PublicKey::from_openssh(value.trim())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid("SSH key must use Ed25519"));
    }
    key.to_openssh().map_err(io::Error::other)
}

fn validate_hub_response(
    response: EnrollmentResponse,
    expected_machine_id: &str,
) -> io::Result<ValidatedHubResponse> {
    if response.machine_id != expected_machine_id {
        return Err(invalid(
            "Hub enrollment response machine_id does not match the request",
        ));
    }
    validate_identifier(&response.name, "Hub-assigned name")?;
    let control_secret = response.control_secret.trim().to_owned();
    if control_secret.len() < 16 {
        return Err(invalid("Hub response is missing a valid control_secret"));
    }
    if response.remote_port < 1024 {
        return Err(invalid(
            "Hub response remote_port must be an unprivileged port",
        ));
    }
    let (gateways, known_hosts) = validate_gateways(response.gateways)?;
    let authorized_keys = validate_operator_keys(
        response.operator_ssh_public_keys,
        response.operator_ssh_public_key,
    )?;
    Ok(ValidatedHubResponse {
        machine_id: response.machine_id,
        name: response.name,
        control_secret,
        remote_port: response.remote_port,
        gateways,
        known_hosts,
        authorized_keys,
    })
}

fn write_enrolled_state(
    state: &Path,
    response: ValidatedHubResponse,
    outbound_key: &str,
    server_key: &str,
) -> io::Result<()> {
    hostlink_core::write_new_private_bytes(
        &state.join("machine.id"),
        response.machine_id.as_bytes(),
    )?;
    hostlink_core::write_new_private_bytes(&state.join("identity"), outbound_key.as_bytes())?;
    hostlink_core::write_new_private_bytes(
        &state.join("ssh_host_ed25519_key"),
        server_key.as_bytes(),
    )?;
    hostlink_core::write_new_private_bytes(
        &state.join("known_hosts"),
        response.known_hosts.as_bytes(),
    )?;
    hostlink_core::write_new_private_bytes(
        &state.join("authorized_keys"),
        response.authorized_keys.as_bytes(),
    )?;
    hostlink_core::write_new_private_bytes(
        &state.join("control.secret"),
        response.control_secret.as_bytes(),
    )?;

    let config = AgentConfigDocument {
        version: 1,
        name: response.name,
        listen: "127.0.0.1:27391",
        secret_env: "",
        secret_file: "control.secret",
        // The published config is root/agent/agent.json; the updater and runtime share root/jobs.
        jobs_dir: "../jobs",
        ssh: SshConfigDocument {
            gateways: response.gateways,
            remote_port: response.remote_port,
            identity: "identity",
            known_hosts: "known_hosts",
            reconnect_seconds: 5,
        },
        embedded_ssh_server: EmbeddedSshDocument {
            user: LOGICAL_SSH_USER,
            host_key: "ssh_host_ed25519_key",
            authorized_keys: "authorized_keys",
            port: 27322,
        },
    };
    let config_bytes = serde_json::to_vec_pretty(&config).map_err(io::Error::other)?;
    let config_path = state.join(CONFIG_FILE);
    hostlink_core::write_new_private_bytes(&config_path, &config_bytes)?;
    AgentConfig::load(&config_path)?.runtime()?;
    Ok(())
}

fn write_enrolled_state_or_cleanup(
    state: &Path,
    response: ValidatedHubResponse,
    outbound_key: &str,
    server_key: &str,
) -> io::Result<()> {
    if let Err(error) = write_enrolled_state(state, response, outbound_key, server_key) {
        return match std::fs::remove_dir_all(state) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::new(
                error.kind(),
                format!(
                    "{error}; failed to remove private enrollment state after failure: {cleanup_error}"
                ),
            )),
        };
    }
    Ok(())
}

fn validate_gateways(gateways: Vec<Gateway>) -> io::Result<(Vec<GatewayEndpointDocument>, String)> {
    if gateways.is_empty() {
        return Err(invalid("Hub response must approve at least one gateway"));
    }
    let mut seen = BTreeSet::new();
    let mut endpoints = Vec::with_capacity(gateways.len());
    let mut known_hosts = String::new();
    for gateway in gateways {
        if !valid_gateway_host(&gateway.host)
            || gateway.user.is_empty()
            || !gateway
                .user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || gateway.port == 0
        {
            return Err(invalid("Hub response contains a malformed gateway"));
        }
        let identity = (gateway.host.to_ascii_lowercase(), gateway.port);
        if !seen.insert(identity) {
            return Err(invalid(
                "Hub response contains duplicate gateway host/port entries",
            ));
        }
        let host_key = normalize_ed25519(&gateway.host_public_key)?;
        let host_pattern = if gateway.port == 22 {
            gateway.host.clone()
        } else {
            format!("[{}]:{}", gateway.host, gateway.port)
        };
        known_hosts.push_str(&format!("{host_pattern} {host_key}\n"));
        endpoints.push(GatewayEndpointDocument {
            host: gateway.host,
            user: gateway.user,
            port: gateway.port,
        });
    }
    Ok((endpoints, known_hosts))
}

fn valid_gateway_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn validate_operator_keys(keys: Option<Vec<String>>, legacy: Option<String>) -> io::Result<String> {
    let keys = keys.unwrap_or_else(|| legacy.clone().into_iter().collect());
    if keys.is_empty() {
        return Err(invalid(
            "Hub response must contain operator SSH public keys",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(keys.len());
    for key in keys {
        let key = normalize_ed25519(&key)?;
        if !seen.insert(key.clone()) {
            return Err(invalid("Hub response contains duplicate operator SSH keys"));
        }
        normalized.push(key);
    }
    if let Some(legacy) = legacy {
        let legacy = normalize_ed25519(&legacy)?;
        if normalized.first() != Some(&legacy) {
            return Err(invalid("Hub operator SSH key aliases conflict"));
        }
    }
    Ok(normalized
        .into_iter()
        .map(|key| format!("{key}\n"))
        .collect())
}

fn endpoint_url(hub_url: &str) -> io::Result<String> {
    let url = hub_url.trim_end_matches('/');
    if !url.starts_with("https://") || url.contains('@') || url.contains('?') || url.contains('#') {
        return Err(invalid(
            "hub-url must be an HTTPS origin or /v1/enroll endpoint",
        ));
    }
    if url.ends_with("/v1/enroll") {
        Ok(url.to_owned())
    } else {
        Ok(format!("{url}/v1/enroll"))
    }
}

fn local_hostname() -> io::Result<String> {
    let hostname = hostname::get()
        .map_err(io::Error::other)?
        .to_string_lossy()
        .trim()
        .to_owned();
    if hostname.is_empty() || hostname.len() > 255 || hostname.contains(['\r', '\n']) {
        return Err(invalid("local hostname is empty or invalid"));
    }
    Ok(hostname)
}

fn canonical_label(hostname: &str) -> String {
    let label: String = hostname
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    label
        .chars()
        .take(128)
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn validate_identifier(value: &str, label: &str) -> io::Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(invalid(format!(
            "{label} must be a canonical ASCII identifier"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("test key")
            .public_key()
            .to_openssh()
            .expect("public key")
    }

    fn response_value(
        machine_id: &str,
        gateway_key: &str,
        operator_keys: &[String],
    ) -> serde_json::Value {
        serde_json::json!({
            "machine_id": machine_id,
            "name": "host-01",
            "control_secret": "0123456789abcdef0123456789abcdef",
            "remote_port": 41000,
            "gateways": [{
                "host": "gateway.example",
                "user": "agent",
                "port": 2222,
                "host_public_key": gateway_key
            }],
            "operator_ssh_public_keys": operator_keys,
            "operator_ssh_public_key": operator_keys.first()
        })
    }

    #[test]
    fn validates_gateway_and_operator_response_material() {
        let gateway_key = key();
        let (endpoints, known_hosts) = validate_gateways(vec![Gateway {
            host: "gateway.example".to_owned(),
            user: "agent".to_owned(),
            port: 2222,
            host_public_key: gateway_key.clone(),
        }])
        .expect("valid gateway");
        assert_eq!(endpoints.len(), 1);
        assert!(known_hosts.starts_with("[gateway.example]:2222 ssh-ed25519 "));
        assert!(
            validate_gateways(vec![
                Gateway {
                    host: "gateway.example".to_owned(),
                    user: "agent".to_owned(),
                    port: 22,
                    host_public_key: gateway_key.clone(),
                },
                Gateway {
                    host: "GATEWAY.EXAMPLE".to_owned(),
                    user: "agent".to_owned(),
                    port: 22,
                    host_public_key: gateway_key,
                }
            ])
            .is_err()
        );
        for host in ["*", "gateway.example,other.example", "bad host", "#comment"] {
            assert!(
                validate_gateways(vec![Gateway {
                    host: host.to_owned(),
                    user: "agent".to_owned(),
                    port: 22,
                    host_public_key: key(),
                }])
                .is_err(),
                "unsafe gateway host accepted: {host}"
            );
        }
        let operator = key();
        assert!(
            validate_operator_keys(Some(vec![operator.clone(), operator.clone()]), None).is_err()
        );
        assert!(validate_operator_keys(Some(vec![key()]), Some(key())).is_err());
        assert!(validate_operator_keys(Some(vec!["not-a-key".to_owned()]), None).is_err());
        assert!(validate_operator_keys(None, None).is_err());
    }

    #[test]
    fn hub_response_identity_and_required_secret_are_fail_closed() {
        let gateway = key();
        let operators = vec![key(), key()];
        let fixture = response_value("expected", &gateway, &operators);
        let parsed: EnrollmentResponse =
            serde_json::from_value(fixture.clone()).expect("typed Hub fixture parses");
        let validated = validate_hub_response(parsed, "expected").expect("Hub reply validates");
        assert_eq!(validated.name, "host-01");
        assert_eq!(validated.remote_port, 41000);
        assert_eq!(validated.gateways.len(), 1);
        assert!(
            validated
                .known_hosts
                .starts_with("[gateway.example]:2222 ssh-ed25519 ")
        );
        assert_eq!(validated.authorized_keys.lines().count(), 2);
        assert!(
            validate_hub_response(
                serde_json::from_value(fixture).expect("typed Hub fixture parses"),
                "foreign-id"
            )
            .is_err()
        );
        assert!(
            validate_hub_response(
                serde_json::from_value(response_value("expected", &gateway, &operators)).unwrap(),
                "expected"
            )
            .is_ok()
        );
        let missing_secret = serde_json::json!({
            "machine_id":"expected", "name":"host-01", "remote_port":41000,
            "gateways":[{"host":"gateway.example", "user":"agent", "port":2222, "host_public_key":gateway}],
            "operator_ssh_public_keys":operators
        });
        assert!(serde_json::from_value::<EnrollmentResponse>(missing_secret).is_err());
        let mut empty_secret = response_value("expected", &gateway, &operators);
        empty_secret["control_secret"] = serde_json::json!("");
        assert!(
            validate_hub_response(
                serde_json::from_value(empty_secret).expect("typed response with empty secret"),
                "expected"
            )
            .is_err()
        );
        let mut invalid_port: EnrollmentResponse =
            serde_json::from_value(response_value("expected", &gateway, &operators))
                .expect("valid typed response");
        invalid_port.remote_port = 22;
        assert!(validate_hub_response(invalid_port, "expected").is_err());
    }

    #[test]
    fn generated_ssh_identities_are_independent_and_round_trip() {
        let (outbound, outbound_public) = generate_ed25519_keypair().expect("outbound identity");
        let (server, server_public) = generate_ed25519_keypair().expect("server identity");
        assert_ne!(outbound_public, server_public);
        let loaded_outbound = PrivateKey::from_openssh(&outbound).expect("parse outbound");
        let loaded_server = PrivateKey::from_openssh(&server).expect("parse server");
        assert_eq!(
            normalize_ed25519(
                &loaded_outbound
                    .public_key()
                    .to_openssh()
                    .expect("outbound pub")
            )
            .expect("normalize"),
            outbound_public
        );
        assert_eq!(
            normalize_ed25519(&loaded_server.public_key().to_openssh().expect("server pub"))
                .expect("normalize"),
            server_public
        );
    }

    #[test]
    fn enrollment_request_uses_exact_hub_v1_field_names_and_values() {
        let machine_id = "7a2905df-06b1-4e87-a715-12a75a9ad456";
        let name = "workstation-01";
        let hostname = "workstation";
        let request = EnrollRequest {
            machine_id,
            name,
            hostname,
            username: Some(LOGICAL_SSH_USER),
            os: "windows",
            arch: "x86_64",
            agent_version: "0.1.0",
            transport: "open_ssh",
            persistence_mode: "user-session",
            ssh_public_key: key(),
            ssh_host_public_key: key(),
        };
        let value = serde_json::to_value(request).expect("serialize Hub request");
        let fields = value.as_object().expect("request object");
        assert_eq!(fields.len(), 11);
        assert_eq!(value["machine_id"], machine_id);
        assert_eq!(value["transport"], "open_ssh");
        assert_eq!(value["persistence_mode"], "user-session");
        assert_eq!(value["username"], LOGICAL_SSH_USER);
        assert!(value.get("ssh_public_key").is_some());
        assert!(value.get("ssh_host_public_key").is_some());
    }

    #[test]
    fn enrollment_refuses_existing_or_linked_state_directory_before_network() {
        let directory = tempfile::tempdir().expect("tempdir");
        let existing = directory.path().join("existing");
        std::fs::create_dir(&existing).expect("existing state directory");
        let error = prepare_enrollment(PrepareEnrollmentRequest {
            hub_url: "https://hub.invalid".into(),
            token_file: directory.path().join("missing-token"),
            state_dir: existing.clone(),
            name: None,
        })
        .expect_err("existing state directory is refused");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = directory.path().join("linked-state");
            symlink(&existing, &linked).expect("state symlink");
            assert!(
                prepare_enrollment(PrepareEnrollmentRequest {
                    hub_url: "https://hub.invalid".into(),
                    token_file: directory.path().join("missing-token"),
                    state_dir: linked,
                    name: None,
                })
                .is_err()
            );
            assert_eq!(
                std::fs::read_dir(existing)
                    .expect("target untouched")
                    .count(),
                0
            );
        }
    }

    #[test]
    fn invalid_private_hub_response_is_deleted_and_reports_one_use_outcome() {
        let directory = tempfile::tempdir().expect("tempdir");
        let response_path = directory.path().join("response.json");
        hostlink_core::write_new_private_bytes(&response_path, b"not-json")
            .expect("private invalid response");
        let error = read_validate_and_remove_response(&response_path, "expected")
            .expect_err("invalid response must fail");
        assert!(!response_path.exists(), "private response must be removed");
        assert!(error.to_string().contains("one-use invite"));
        assert!(error.to_string().contains("do not retry"));
    }

    #[test]
    fn generated_config_has_relative_paths_and_loads_from_state_directory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = directory.path().join("private-state");
        hostlink_core::create_private_directory(&state).expect("private state directory");
        let (identity, _) = generate_ed25519_keypair().expect("outbound fixture");
        let (host_key, host_public) = generate_ed25519_keypair().expect("server fixture");
        let (operator_private, operator_public) =
            generate_ed25519_keypair().expect("operator fixture");
        let operator_two = generate_ed25519_keypair()
            .expect("second operator fixture")
            .1;
        let typed: EnrollmentResponse = serde_json::from_value(response_value(
            "expected",
            &host_public,
            &[operator_public, operator_two],
        ))
        .expect("typed Hub response");
        let validated = validate_hub_response(typed, "expected").expect("validate Hub response");
        write_enrolled_state(&state, validated, &identity, &host_key)
            .expect("write enrolled state");
        let serialized_request = serde_json::to_value(EnrollRequest {
            machine_id: "expected",
            name: "host-01",
            hostname: "workstation",
            username: Some(LOGICAL_SSH_USER),
            os: "windows",
            arch: "x86_64",
            agent_version: "0.1.0",
            transport: "open_ssh",
            persistence_mode: "user-session",
            ssh_public_key: key(),
            ssh_host_public_key: key(),
        })
        .expect("serialize Hub request");
        let config_path = state.join(CONFIG_FILE);
        let loaded = AgentConfig::load(&config_path).expect("candidate config loads");
        assert_eq!(loaded.name(), "host-01");
        loaded.runtime().expect("control secret resolves");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(config_path).expect("read config"))
                .expect("json");
        assert_eq!(value["ssh"]["identity"], "identity");
        assert_eq!(value["ssh"]["known_hosts"], "known_hosts");
        assert_eq!(value["secret_file"], "control.secret");
        assert_eq!(value["jobs_dir"], "../jobs");
        assert_eq!(value["ssh"]["remote_port"], 41000);
        assert_eq!(value["embedded_ssh_server"]["user"], "hostlink");
        assert_eq!(
            serialized_request["username"],
            value["embedded_ssh_server"]["user"]
        );
        assert_eq!(
            std::fs::read_to_string(state.join("machine.id")).expect("machine id"),
            "expected"
        );
        assert!(PrivateKey::from_openssh(&operator_private).is_ok());
        #[cfg(unix)]
        for file in [
            "identity",
            "ssh_host_ed25519_key",
            "control.secret",
            "machine.id",
            "agent.json",
        ] {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(state.join(file))
                .expect("private file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{file} permissions");
        }
    }

    #[test]
    fn published_config_and_agent_updater_share_the_root_jobs_directory() {
        let directory = tempfile::tempdir().expect("temporary parent");
        let candidate_parent = directory.path().join("candidate");
        std::fs::create_dir(&candidate_parent).expect("candidate parent");
        let state = candidate_parent.join("agent");
        hostlink_core::create_private_directory(&state).expect("private candidate state");
        let root = directory.path().join("installed-root");
        std::fs::create_dir(&root).expect("fresh install root");

        let (outbound, _) = generate_ed25519_keypair().expect("outbound identity");
        let (host_key, host_public) = generate_ed25519_keypair().expect("server identity");
        let operator = generate_ed25519_keypair().expect("operator identity").1;
        let response: EnrollmentResponse = serde_json::from_value(response_value(
            "expected",
            &host_public,
            std::slice::from_ref(&operator),
        ))
        .expect("typed Hub response");
        let response = validate_hub_response(response, "expected").expect("validated response");
        write_enrolled_state(&state, response, &outbound, &host_key)
            .expect("prepared enrollment state");

        let published = root.join("agent");
        std::fs::rename(&state, &published).expect("publish candidate state");
        let config = AgentConfig::load(published.join(CONFIG_FILE)).expect("installed config");
        let runtime = config.runtime().expect("runtime config");
        std::fs::create_dir(root.join("jobs")).expect("private jobs root");
        assert_eq!(
            runtime
                .jobs_dir
                .canonicalize()
                .expect("resolved runtime jobs"),
            root.join("jobs").canonicalize().expect("install jobs root")
        );

        let active_job = root.join("jobs/job-active");
        std::fs::create_dir_all(&active_job).expect("active job directory");
        std::fs::write(
            active_job.join("state-000000.json"),
            br#"{"version":1,"job":{"job_id":"job-active","state":"running","created_unix_ms":1},"process_identities":{"version":0}}"#,
        )
        .expect("active job state");
        assert_eq!(
            crate::preflight_runtime_update(&root).expect("update preflight"),
            crate::RuntimeUpdatePreflightOutcome::DeferredActiveJobs {
                job_ids: vec!["job-active".to_owned()]
            }
        );
    }

    #[test]
    fn failed_config_validation_removes_control_secret_with_candidate_state() {
        let directory = tempfile::tempdir().expect("temporary parent");
        let state = directory.path().join("private-state");
        hostlink_core::create_private_directory(&state).expect("private state");
        let (_, host_public) = generate_ed25519_keypair().expect("gateway identity");
        let operator = generate_ed25519_keypair().expect("operator identity").1;
        let response: EnrollmentResponse = serde_json::from_value(response_value(
            "expected",
            &host_public,
            std::slice::from_ref(&operator),
        ))
        .expect("typed Hub response");
        let response = validate_hub_response(response, "expected").expect("validated response");

        let error = write_enrolled_state_or_cleanup(&state, response, "invalid-key", "invalid-key")
            .expect_err("invalid private keys must fail config validation");
        let error = one_use_reconciliation_error(error);
        assert!(error.to_string().contains("one-use invite"));
        assert!(!state.exists());
        assert!(!state.join("control.secret").exists());
    }
}
