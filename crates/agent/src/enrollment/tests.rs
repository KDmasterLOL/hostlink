use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use hostlink_hub::{HubConfig, HubService, InviteRequest};
use secrecy::ExposeSecret;
use std::sync::Mutex;
use tower::ServiceExt;

static LISTENER_ADDRESS_TEST_LOCK: Mutex<()> = Mutex::new(());

fn listener_address_test_guard() -> std::sync::MutexGuard<'static, ()> {
    LISTENER_ADDRESS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn reserve_listener_candidates(count: usize) -> Vec<TcpListener> {
    let listeners = AGENT_LISTENER_PORTS
        .clone()
        .filter_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .take(count)
        .collect::<Vec<_>>();
    assert_eq!(listeners.len(), count, "could not reserve test candidates");
    listeners
}

#[test]
fn listener_address_binds_a_nonzero_loopback_port_in_the_selected_range() {
    let _guard = listener_address_test_guard();
    let address = available_loopback_addr().expect("available loopback listener port");

    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    assert!(AGENT_LISTENER_PORTS.contains(&address.port()));
    TcpListener::bind(address).expect("probe listener is released before returning");
}

#[test]
fn listener_address_retries_an_occupied_candidate() {
    let _guard = listener_address_test_guard();
    let mut listeners = reserve_listener_candidates(2);
    let occupied_port = listeners[0].local_addr().unwrap().port();
    let available_port = listeners[1].local_addr().unwrap().port();
    drop(listeners.remove(1));

    let address = available_loopback_addr_from([occupied_port, available_port].into_iter())
        .expect("retry should select the next free candidate");

    assert_eq!(address.port(), available_port);
    assert!(address.ip().is_loopback());
}

#[test]
fn listener_address_allocations_avoid_ports_still_held_by_prior_probes() {
    let _guard = listener_address_test_guard();
    let mut listeners = Vec::new();
    let mut ports = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let address = available_loopback_addr().expect("available loopback listener port");
        assert!(ports.insert(address.port()), "port was reused while held");
        listeners.push(TcpListener::bind(address).expect("reserve selected port"));
    }
}

#[test]
fn listener_address_fails_after_bounded_candidates_are_occupied() {
    let _guard = listener_address_test_guard();
    let listeners = reserve_listener_candidates(LISTENER_PORT_ATTEMPTS);
    let ports = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect::<Vec<_>>();

    let error = available_loopback_addr_from(ports.into_iter())
        .expect_err("all bounded candidates are occupied");

    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    assert!(error.to_string().contains("after 32 attempts"));
    drop(listeners);
}

fn key() -> (PrivateKey, String) {
    let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    (key, public)
}

#[cfg(windows)]
#[test]
fn fresh_root_accepts_dos_drive_path_without_allowing_alias_or_network_root() {
    let fixture = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("fresh current-user Windows fixture");
    fs::remove_dir(fixture.path()).expect("remove empty fixture before private creation");
    PrivateDir::ensure(fixture.path()).expect("create current-user fixture with a protected ACL");
    let canonical = fs::canonicalize(fixture.path()).expect("canonical Windows path");
    assert_ne!(
        canonical,
        fixture.path(),
        "Windows canonicalize must be allowed to return extended-length syntax"
    );
    ensure_fresh_root_parent(&fixture.path().join("fresh-agent"))
        .expect("ordinary private DOS-drive directory is safe for fresh enrollment");

    let inner = fixture.path().join("inner");
    fs::create_dir(&inner).expect("create traversal fixture");
    assert!(
        ensure_fresh_root_parent(&inner.join("..").join("fresh-agent")).is_err(),
        "parent traversal is still rejected"
    );
    assert!(
        ensure_fresh_root_parent(Path::new(r"\\untrusted.example\share\new-agent")).is_err(),
        "a network share cannot be adopted as a local Agent install root"
    );
}

#[test]
fn rejects_non_https_and_ambiguous_or_untrusted_response() {
    assert!(parse_hub_url("http://hub.invalid").is_err());
    assert!(parse_hub_url("https://user:pass@hub.invalid").is_err());
    assert!(parse_hub_url("not a URL").is_err());
    let id = MachineId::parse(Uuid::new_v4().to_string()).unwrap();
    let (_, reverse) = key();
    let (_, host) = key();
    let (_, operator) = key();
    let (_, gateway_pin) = key();
    let response = EnrollResponse {
        host: hostlink_hub::RegisteredHost {
            machine_id: id.clone(),
            name: "test-host".into(),
            display_name: None,
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            agent_version: "0.1.0".into(),
            ssh_public_key: reverse.clone(),
            ssh_host_public_key: host.clone(),
            remote_port: 32000,
            enrolled_at: 1,
            updated_at: 1,
        },
        gateways: vec![GatewayEndpoint {
            host: "gw.invalid".into(),
            user: "agent".into(),
            port: 22,
            host_public_key: gateway_pin,
        }],
        operator_ssh_public_keys: vec![operator],
    };
    assert!(validate_response(&response, &id, "test-host", &reverse, &host, None).is_ok());
    assert!(validate_response(&response, &id, "wrong-name", &reverse, &host, None).is_err());
    let wrong_machine_id = MachineId::parse(Uuid::new_v4().to_string()).unwrap();
    assert!(
        validate_response(
            &response,
            &wrong_machine_id,
            "test-host",
            &reverse,
            &host,
            None
        )
        .is_err()
    );
    assert!(validate_response(&response, &id, "test-host", &reverse, &host, Some(1)).is_err());
    let mut ambiguous = response.clone();
    let (_, second_gateway_pin) = key();
    ambiguous.gateways.push(GatewayEndpoint {
        host: "other-gateway.invalid".into(),
        user: "agent".into(),
        port: 2222,
        host_public_key: second_gateway_pin,
    });
    assert!(validate_response(&ambiguous, &id, "test-host", &reverse, &host, None).is_err());
    let selected =
        validate_response(&ambiguous, &id, "test-host", &reverse, &host, Some(1)).unwrap();
    assert_eq!(selected[0].host, "other-gateway.invalid");
    assert_eq!(selected[1].host, "gw.invalid");
    let mut duplicate_keys = response.clone();
    duplicate_keys
        .operator_ssh_public_keys
        .push(duplicate_keys.operator_ssh_public_keys[0].clone());
    assert!(validate_response(&duplicate_keys, &id, "test-host", &reverse, &host, None).is_err());
    let secret = "secret-token-must-not-appear-in-debug";
    let request = EnrollRequest {
        token: SecretString::from(secret.to_owned()),
        machine_id: id,
        name: "test-host".into(),
        hostname: "host".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        ssh_public_key: reverse,
        ssh_host_public_key: host,
    };
    assert!(!format!("{request:?}").contains(secret));
}

#[tokio::test]
async fn fresh_enrollment_publishes_private_config_once_against_local_hub_v2() {
    let fixture = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("isolated disposable fixture under Agent crate");
    #[cfg(windows)]
    {
        fs::remove_dir(fixture.path()).expect("remove empty fixture before private creation");
        PrivateDir::ensure(fixture.path())
            .expect("create private enrollment fixture with protected current-user ACL");
    }
    let operator = "operator-test-secret-000000000000000000000000000000000000";
    let gateway_lookup = "gateway-test-secret-000000000000000000000000000000";
    let projection = fixture.path().join("projection");
    PrivateDir::open(fixture.path())
        .unwrap()
        .create_dir("projection")
        .unwrap();
    let gateway_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let alternate_gateway_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let controller_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
    let gateway = GatewayEndpoint {
        host: "127.0.0.1".into(),
        user: "hostlink".into(),
        port: 22,
        host_public_key: gateway_key.public_key().to_openssh().unwrap(),
    };
    let alternate_gateway = GatewayEndpoint {
        host: "127.0.0.2".into(),
        user: "hostlink".into(),
        port: 2222,
        host_public_key: alternate_gateway_key.public_key().to_openssh().unwrap(),
    };
    let service = HubService::new(HubConfig {
        listen: "127.0.0.1:43210".parse().unwrap(),
        public_url: "https://hub.invalid".into(),
        state_root: fixture.path().join("hostlink-hub-v2"),
        authorized_keys: projection.join("hostlink-v2-authorized_keys"),
        gateways: vec![gateway, alternate_gateway],
        operator_ssh_public_keys: vec![controller_key.public_key().to_openssh().unwrap()],
        operator_token: SecretString::from(operator.to_owned()),
        gateway_lookup_token: SecretString::from(gateway_lookup.to_owned()),
        port_from: 32000,
        port_to: 32020,
        reserved_ports: std::collections::BTreeSet::new(),
    })
    .expect("isolated v2 Hub fixture");
    let app = hostlink_hub::router(service);
    let invite_body = serde_json::to_vec(&InviteRequest {
        ttl_seconds: 900,
        name: Some("enroll-test".into()),
        rotate_machine_id: None,
    })
    .unwrap();
    let invite_response = app
        .clone()
        .oneshot(
            Request::post("/v2/invites")
                .header("authorization", format!("Bearer {operator}"))
                .header("content-type", "application/json")
                .body(Body::from(invite_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(invite_response.status().is_success());
    let invite: hostlink_hub::InviteResponse = serde_json::from_slice(
        &to_bytes(invite_response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    let token_file = fixture.path().join("invite-token");
    write_private_new(&token_file, invite.token.expose_secret().as_bytes()).unwrap();
    let install_root = fixture.path().join("fresh-agent");
    let options = EnrollmentOptions {
        hub_url: "https://hub.invalid".into(),
        token_file,
        install_root: install_root.clone(),
        name: "enroll-test".into(),
        user: "agent-user".into(),
        gateway_index: Some(1),
        retain_pending: true,
    };
    let inventory_app = app.clone();
    let replay_app = app.clone();
    let replay_request = std::sync::Arc::new(std::sync::Mutex::new(None));
    let replay_capture = replay_request.clone();
    let published_result = prepare_enrollment_using(&options, move |_, request| async move {
        *replay_capture.lock().unwrap() = Some(request.clone());
        let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
        let response = app
            .oneshot(
                Request::post("/v2/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .map_err(io::Error::other)?,
            )
            .await
            .map_err(io::Error::other)?;
        if response.status() != axum::http::StatusCode::CREATED {
            let status = response.status();
            let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                .await
                .map_err(io::Error::other)?;
            return Err(io::Error::other(format!(
                "Hub v2 fixture rejected enrollment ({status}: {})",
                String::from_utf8_lossy(&body)
            )));
        }
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .map_err(io::Error::other)?;
        serde_json::from_slice(&body).map_err(io::Error::other)
    })
    .await;
    let published = published_result.unwrap_or_else(|error| {
        let entries = fs::read_dir(&install_root)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| {
                        let name = entry.file_name();
                        let children = fs::read_dir(entry.path())
                            .map(|items| {
                                items
                                    .filter_map(Result::ok)
                                    .map(|item| item.file_name())
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        (name, children)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        panic!("enrollment fixture error: {error:?}; root entries: {entries:?}");
    });
    assert_eq!(published.machine_id.len(), 36);
    let config: AgentConfig =
        serde_json::from_slice(&fs::read(&published.config_path).unwrap()).unwrap();
    let board = config
        .board_listen
        .expect("new managed Agent has local Apalis board");
    assert!(board.ip().is_loopback());
    assert_ne!(board.port(), 0);
    assert_ne!(board, config.listen, "board and SSH use distinct listeners");
    assert!((32000..=32020).contains(&config.gateway.as_ref().unwrap().remote_port));
    assert_eq!(config.gateway.as_ref().unwrap().host, "127.0.0.2");
    assert_eq!(config.gateway_alternates.len(), 1);
    assert_eq!(config.gateway_alternates[0].host, "127.0.0.1");
    assert!(config.validate().is_ok());
    assert_eq!(config.jobs_root, install_root.join("jobs"));
    assert!(config.jobs_root.is_dir());
    assert!(config.jobs_root.join("jobs.db").is_file());
    assert!(
        !published
            .config_path
            .parent()
            .unwrap()
            .join("jobs")
            .exists(),
        "the job store must not be hidden under state/"
    );
    let state = published.config_path.parent().unwrap();
    let identity: EnrollmentIdentity =
        serde_json::from_slice(&fs::read(state.join("machine.json")).unwrap()).unwrap();
    assert_eq!(identity.machine_id.to_string(), published.machine_id);
    assert!(state.join("manifest.json").is_file());
    assert!(state.join("gateway_host_key_1").is_file());
    assert!(install_root.join("enrollment.pending").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in [
            "agent.json",
            "gateway_identity",
            "host_key",
            "authorized_keys",
        ] {
            assert_eq!(
                fs::metadata(state.join(file)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let replay = replay_request.lock().unwrap().take().unwrap();
    let replay_response = replay_app
        .oneshot(
            Request::post("/v2/enroll")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&replay).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        replay_response.status(),
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert!(
        prepare_enrollment(&options).await.is_err(),
        "existing root must not be adopted or reenrolled"
    );
    let hosts_response = inventory_app
        .oneshot(
            Request::get("/v2/hosts")
                .header("authorization", format!("Bearer {operator}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let hosts: serde_json::Value = serde_json::from_slice(
        &to_bytes(hosts_response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(hosts["hosts"].as_array().unwrap().len(), 1);
}
