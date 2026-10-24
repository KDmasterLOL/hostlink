use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CACHE_CONTROL},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::CommandFactory;
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::{
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering as AtomicOrdering},
    thread,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[test]
fn structured_hub_audit_is_machine_readable_and_token_free() {
    let line = hub_audit_line(
        "agent.enrolled",
        HubAuditFields {
            machine_id: Some("machine-1".to_owned()),
            agent_name: Some("generic-target".to_owned()),
            remote_port: Some(18403),
            reenroll: Some(false),
            ..HubAuditFields::default()
        },
    );
    let value: serde_json::Value = serde_json::from_str(&line).expect("audit json");
    assert_eq!(value["schema_version"], HUB_AUDIT_SCHEMA_VERSION);
    assert_eq!(value["event_code"], "agent.enrolled");
    assert_eq!(value["component"], "onec_hub");
    assert_eq!(value["remote_port"], 18403);
    assert!(!line.contains("token"));
    assert!(!line.contains("secret"));
}

#[test]
fn overload_audit_is_secret_free_and_monotonic_count_is_serialized() {
    let line = hub_audit_line(
        "request.overloaded",
        HubAuditFields {
            overload_count: Some(42),
            ..HubAuditFields::default()
        },
    );
    let value: serde_json::Value = serde_json::from_str(&line).expect("audit json");
    assert_eq!(value["event_code"], "request.overloaded");
    assert_eq!(value["overload_count"], 42);
    assert!(!line.contains("token"));
    assert!(!line.contains("secret"));
}

#[test]
fn root_help_uses_standard_clap_layout() {
    let help = Cli::command()
        .try_get_matches_from(["hostlink-hub", "--help"])
        .expect_err("help exits through DisplayHelp")
        .to_string();
    assert!(help.contains("Usage: hostlink-hub <COMMAND>"));
    assert!(help.contains("Commands:"));
    assert!(help.contains("Options:"));
    assert!(help.contains("Print help"));
    assert!(help.contains("Print version"));
}

fn config(dir: &Path) -> HubConfig {
    HubConfig {
        version: 1,
        listen: "127.0.0.1:27400".into(),
        public_url: HubHttpsUrl::parse("https://hub.example.test").expect("public URL"),
        gateways: vec![hostlink_hub::GatewayEndpoint {
            host: "gateway.example.test".into(),
            user: "onec-agent".into(),
            port: 22,
            host_public_key: key("gateway-host"),
        }],
        controller_ssh_user: Some("operator".into()),
        operator_ssh_public_key: key("operator"),
        operator_ssh_public_keys: Vec::new(),
        authorized_keys: dir.join("authorized_keys"),
        state_file: dir.join("state.json"),
        operator_token_env: "TEST_TOKEN".into(),
        agent_secret_key_env: "TEST_AGENT_SECRET_KEY".into(),
        ssh_lookup_token_env: Some("TEST_SSH_LOOKUP_TOKEN".into()),
        probe_gateway_ports_locally: true,
        port_from: 41000,
        port_to: 41002,
        reserved_ports: Vec::new(),
    }
}

fn key(seed: &str) -> String {
    let bytes = Sha256::digest(seed.as_bytes());
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    blob.extend_from_slice(&(11_u32).to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&(32_u32).to_be_bytes());
    blob.extend_from_slice(&bytes);
    format!(
        "ssh-ed25519 {} fixture-{seed}",
        BASE64_STANDARD.encode(blob)
    )
}

fn test_app(config: HubConfig) -> Arc<App> {
    Arc::new(App {
        config,
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    })
}

fn agent_record(machine_id: &str, seed: &str, remote_port: u16) -> AgentRecord {
    AgentRecord {
        id: format!("id-{machine_id}"),
        machine_id: machine_id.to_owned(),
        name: machine_id.to_owned(),
        display_name: None,
        hostname: machine_id.to_owned(),
        username: None,
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: None,
        remote_port,
        ssh_public_key: key(seed),
        ssh_host_public_key: None,
        control_credential_nonce: None,
        enrolled_at: 1,
        updated_at: 1,
    }
}

fn wait_for_test_path(path: &Path) {
    for _ in 0..1_000 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {}", path.display());
}

#[test]
fn hub_state_lock_holder_child() {
    let Some(root) = env::var_os("ONEC_HUB_TEST_LOCK_ROOT") else {
        return;
    };
    let ready =
        PathBuf::from(env::var_os("ONEC_HUB_TEST_LOCK_READY").expect("lock child ready path"));
    let mut hub_config = config(Path::new(&root));
    hub_config.probe_gateway_ports_locally = false;
    let app = test_app(hub_config);
    let _writer = app.lock_state_writer().expect("child state writer");
    fs::write(&ready, b"locked").expect("publish lock-ready marker");
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn hub_state_mutation_child() {
    let Some(root) = env::var_os("ONEC_HUB_TEST_WRITER_ROOT") else {
        return;
    };
    let invitation_key = env::var("ONEC_HUB_TEST_WRITER_KEY").expect("writer key");
    let ready =
        PathBuf::from(env::var_os("ONEC_HUB_TEST_WRITER_READY").expect("writer ready path"));
    let go = PathBuf::from(env::var_os("ONEC_HUB_TEST_WRITER_GO").expect("writer go path"));
    let attempting = env::var_os("ONEC_HUB_TEST_WRITER_ATTEMPTING").map(PathBuf::from);
    let locked = env::var_os("ONEC_HUB_TEST_WRITER_LOCKED").map(PathBuf::from);
    let release = env::var_os("ONEC_HUB_TEST_WRITER_RELEASE").map(PathBuf::from);

    fs::write(&ready, b"ready").expect("publish writer-ready marker");
    wait_for_test_path(&go);
    if let Some(attempting) = &attempting {
        fs::write(attempting, b"attempting").expect("publish writer-attempting marker");
    }

    let mut hub_config = config(Path::new(&root));
    hub_config.probe_gateway_ports_locally = false;
    let app = test_app(hub_config);
    let mut writer = app.lock_state_writer().expect("child state writer");
    if let Some(locked) = &locked {
        fs::write(locked, b"locked").expect("publish writer-locked marker");
    }
    writer.state_mut().invitations.insert(
        invitation_key.clone(),
        Invitation {
            created_at: 1,
            expires_at: i64::MAX,
            used: false,
            name_hint: Some(invitation_key),
        },
    );
    if let Some(release) = &release {
        wait_for_test_path(release);
    }
    writer.commit(false).expect("child state commit");
}

#[test]
fn hub_serve_startup_child() {
    let Some(root) = env::var_os("ONEC_HUB_TEST_SERVE_ROOT") else {
        return;
    };
    let listen = env::var("ONEC_HUB_TEST_SERVE_LISTEN").expect("serve child listen address");
    let mut hub_config = config(Path::new(&root));
    hub_config.listen = listen;
    let app = App {
        config: hub_config,
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(serve(app))
        .expect("serve child");
}

#[test]
fn regression_inv_060_hub_accepts_multiple_controller_operator_keys() {
    let dir = tempdir().expect("tempdir");
    let mut config = config(dir.path());
    let first = key("operator-one");
    let second = key("operator-two");
    config.operator_ssh_public_key = first.clone();
    config.operator_ssh_public_keys = vec![first.clone(), second.clone()];

    config.validate().expect("multi-controller config");
    assert_eq!(
        config
            .normalized_operator_ssh_public_keys()
            .expect("normalized operator keys"),
        vec![
            normalize_public_key(&first).expect("first operator key"),
            normalize_public_key(&second).expect("second operator key"),
        ]
    );
}

#[test]
fn regression_inv_060_hub_rejects_ambiguous_operator_key_configuration() {
    let dir = tempdir().expect("tempdir");
    let mut config = config(dir.path());
    config.operator_ssh_public_key = key("legacy-primary");
    config.operator_ssh_public_keys = vec![key("different-primary")];
    assert!(config.validate().is_err());

    config.operator_ssh_public_key = key("duplicate");
    config.operator_ssh_public_keys = vec![key("duplicate"), key("duplicate")];
    assert!(config.validate().is_err());
}

fn test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test Tokio runtime")
}

fn api_request(
    app: Arc<App>,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let body = if body.is_null() {
        Body::empty()
    } else {
        Body::from(serde_json::to_vec(body).expect("request JSON"))
    };
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = request.body(body).expect("test API request");
    let response = test_runtime()
        .block_on(router(app).oneshot(request))
        .expect("test API response");
    let status = response.status().as_u16();
    let bytes = test_runtime()
        .block_on(to_bytes(response.into_body(), usize::MAX))
        .expect("test API response body");
    let body = serde_json::from_slice(&bytes).expect("HTTP response JSON");
    (status, body)
}

fn response_for(app: Arc<App>, request: Request<Body>) -> axum::response::Response {
    test_runtime()
        .block_on(router(app).oneshot(request))
        .expect("test router response")
}

async fn response_json_async(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn response_json(response: axum::response::Response) -> serde_json::Value {
    test_runtime().block_on(response_json_async(response))
}

#[test]
fn domain_responses_return_after_releasing_state_writer() {
    let dir = tempdir().expect("tempdir");
    let app = test_app(config(dir.path()));
    let headers = axum::http::HeaderMap::from_iter([(
        "authorization".parse().unwrap(),
        format!("Bearer {}", app.operator_token.expose_secret())
            .parse()
            .unwrap(),
    )]);
    let response = remove_agent_request(&headers, &app, "missing").expect("remove response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    drop(response);
    assert!(app.state_writer.try_lock().is_ok());

    let enroll_headers = axum::http::HeaderMap::from_iter([(
        "authorization".parse().unwrap(),
        "Bearer nonexistent-invite".parse().unwrap(),
    )]);
    let body = axum::body::Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "machine_id": "machine-a",
            "name": "server-a",
            "hostname": "server-a",
            "os": "windows",
            "arch": "x86_64",
            "agent_version": "0.1.0",
            "transport": "open_ssh",
            "ssh_public_key": key("agent-a"),
        }))
        .expect("enrollment body"),
    );
    let response = enroll_request(&enroll_headers, &body, &app).expect("enrollment response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    drop(response);
    assert!(app.state_writer.try_lock().is_ok());
}

#[test]
fn invite_commit_uncertainty_returns_typed_response_without_token() {
    let response = invite_commit_error(StateCommitError::CommitUncertain(io::Error::other(
        "injected post-publication durability failure",
    )));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response);
    assert_eq!(body["error"], "state_commit_uncertain");
    assert!(body.get("token").is_none());
}

#[test]
fn enrollment_commit_uncertainty_returns_typed_response_without_control_secret() {
    let response = write_enrollment_commit_error(StateCommitError::CommitUncertain(
        io::Error::other("injected post-publication enrollment durability failure"),
    ));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response_json(response);
    assert_eq!(body["error"], "state_commit_uncertain");
    assert!(body.get("control_secret").is_none());
}

#[test]
fn router_middleware_rejects_overload_with_no_store_json() {
    let runtime = test_runtime();
    runtime.block_on(async {
        let started = Arc::new(AtomicBool::new(false));
        let handler_started = Arc::clone(&started);
        let app = Router::new().route(
            "/",
            get(move || {
                let handler_started = Arc::clone(&handler_started);
                async move {
                    handler_started.store(true, AtomicOrdering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    "ok"
                }
            }),
        );
        let app = with_request_middleware(app, 1, Duration::from_secs(1));
        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/").body(Body::empty()).unwrap()),
        );
        while !started.load(AtomicOrdering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response_json_async(response).await["error"], "overloaded");
        first.await.unwrap().unwrap();
    });
}

#[test]
fn router_middleware_maps_timeout_to_no_store_json() {
    let runtime = test_runtime();
    runtime.block_on(async {
        let app = Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                "late"
            }),
        );
        let response = with_request_middleware(app, 1, Duration::from_millis(5))
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            response_json_async(response).await["error"],
            "request_timeout"
        );
    });
}

#[test]
fn router_rejects_request_body_over_64_kib_with_stable_json() {
    let dir = tempdir().expect("tempdir");
    let app = test_app(config(dir.path()));
    let request = Request::post("/v1/enroll")
        .header("authorization", "Bearer unused")
        .body(Body::from(vec![b'x'; 64 * 1024 + 1]))
        .expect("oversized request");
    let response = response_for(app, request);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        response_json(response),
        serde_json::json!({
            "error": "bad_request",
            "message": "request body is invalid or too large"
        })
    );
}

#[test]
fn unknown_route_returns_legacy_not_found_json_with_no_store() {
    let dir = tempdir().expect("tempdir");
    let response = response_for(
        test_app(config(dir.path())),
        Request::get("/unknown").body(Body::empty()).unwrap(),
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        response_json(response),
        serde_json::json!({"error":"not_found","message":"endpoint not found"})
    );
}

#[test]
fn method_mismatch_preserves_legacy_not_found_behavior() {
    let dir = tempdir().expect("tempdir");
    let response = response_for(
        test_app(config(dir.path())),
        Request::post("/healthz").body(Body::empty()).unwrap(),
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(
        response_json(response),
        serde_json::json!({"error":"not_found","message":"endpoint not found"})
    );
}

fn wait_for_hub_health(address: std::net::SocketAddr, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(mut stream) = TcpStream::connect(address) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
            let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if stream.write_all(request).is_ok() {
                let mut response = Vec::with_capacity(1024);
                let mut chunk = [0_u8; 512];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => {
                            response.extend_from_slice(&chunk[..read]);
                            if response.windows(4).any(|window| window == b"\r\n\r\n")
                                || response.len() >= 8 * 1024
                            {
                                break;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if response.starts_with(b"HTTP/1.1 200") {
                    return true;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn wire_only_secret_response_serializes_exact_value() {
    let response = InviteResponse {
        token: "wire-secret-sentinel".into(),
        expires_at: 123,
        public_url: HubHttpsUrl::parse("https://hub.example.test").expect("public URL"),
    };
    let value = serde_json::to_value(&response).expect("wire response");
    assert_eq!(value["token"], "wire-secret-sentinel");
    assert_eq!(value["expires_at"], 123);
}

#[test]
fn regression_inv_004_hub_info_requires_operator_and_returns_public_url() {
    let dir = tempdir().expect("tempdir");
    let app = Arc::new(App {
        config: config(dir.path()),
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    });

    let (status, _) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/info",
        None,
        &serde_json::Value::Null,
    );
    assert_eq!(status, 401);

    let (status, body) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/info",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(
        body["public_url"],
        serde_json::to_value(&app.config.public_url).unwrap()
    );
    assert_eq!(
        body["capabilities"],
        serde_json::json!([
            "agents.secret-free-inventory-v1",
            "agents.control-credential-v1",
            "gateway.multi-edge-v1"
        ])
    );
    assert_eq!(
        body["gateways"],
        serde_json::json!([{
            "host": app.config.gateways[0].host,
            "user": "operator",
            "port": app.config.gateways[0].port,
            "host_public_key": app.config.gateways[0].host_public_key
        }])
    );
}

#[test]
fn legacy_hub_info_does_not_advertise_multi_edge_controller_routes() {
    let dir = tempdir().expect("tempdir");
    let mut legacy_config = config(dir.path());
    legacy_config.controller_ssh_user = None;
    let app = Arc::new(App {
        config: legacy_config,
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    });

    let (status, body) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/info",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );

    assert_eq!(status, 200);
    assert_eq!(body["gateways"], serde_json::json!([]));
    assert_eq!(
        body["capabilities"],
        serde_json::json!([
            "agents.secret-free-inventory-v1",
            "agents.control-credential-v1"
        ])
    );
}

#[test]
fn enrollment_api_is_one_use_discoverable_and_revocable() {
    let dir = tempdir().expect("tempdir");
    let app = Arc::new(App {
        config: config(dir.path()),
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    });

    let (status, invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);
    let token = invite["token"].as_str().expect("invite token").to_owned();
    let invite_only_state: serde_json::Value = serde_json::from_slice(
        &fs::read(dir.path().join("state.json")).expect("invite-only hub state"),
    )
    .expect("parse invite-only hub state");
    assert_eq!(invite_only_state["version"], LEGACY_STATE_VERSION);

    let enrollment = serde_json::json!({
        "machine_id": "machine-a",
        "name": "ignored-client-name",
        "hostname": "SERVER-A",
        "username": "TIS",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.1.0",
        "transport": "open_ssh",
        "persistence_mode": "user-session",
        "ssh_public_key": key("api"),
        "ssh_host_public_key": key("host"),
    });
    let (status, enrolled) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&token),
        &enrollment,
    );
    assert_eq!(status, 200);
    assert_eq!(enrolled["name"], "server-a");
    let agent_id = enrolled["id"].as_str().expect("agent id").to_owned();
    let remote_port = enrolled["remote_port"].as_u64().expect("remote port");
    assert!((41000..=41002).contains(&remote_port));
    let first_control_secret = enrolled["control_secret"]
        .as_str()
        .expect("first control secret")
        .to_owned();
    assert_eq!(first_control_secret.len(), 64);
    assert_eq!(
        enrolled["operator_ssh_public_key"],
        normalize_public_key(&key("operator")).expect("normalized operator key")
    );
    assert_eq!(
        enrolled["operator_ssh_public_keys"],
        serde_json::json!([
            normalize_public_key(&key("operator")).expect("normalized operator key")
        ])
    );
    assert_eq!(
        enrolled["gateways"],
        serde_json::to_value(&app.config.gateways).expect("gateway topology")
    );
    assert_eq!(enrolled["gateway_host"], app.config.gateways[0].host);
    let persisted = fs::read_to_string(dir.path().join("state.json")).expect("hub state");
    let persisted_json: serde_json::Value =
        serde_json::from_str(&persisted).expect("parse enrolled hub state");
    assert_eq!(persisted_json["version"], STATE_VERSION);
    assert!(!persisted.contains("control_secret"));
    assert!(!persisted.contains(&first_control_secret));
    assert!(persisted.contains("control_credential_nonce"));

    let (status, listed) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(listed["agents"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["agents"][0]["machine_id"], "machine-a");
    assert!(
        listed["agents"][0].get("control_secret").is_none(),
        "bulk inventory must not expose control credentials"
    );
    assert_eq!(listed["agents"][0]["username"], "TIS");
    assert_eq!(listed["agents"][0]["persistence_mode"], "user-session");
    let first_control_credential_nonce = listed["agents"][0]["control_credential_nonce"]
        .as_str()
        .expect("first control credential nonce")
        .to_owned();
    assert_eq!(first_control_credential_nonce.len(), 64);
    assert_eq!(
        listed["agents"][0]["ssh_host_public_key"],
        normalize_public_key(&key("host")).expect("normalized host key")
    );
    let (status, unauthorized_credential) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents/machine-a/control-credential",
        None,
        &serde_json::Value::Null,
    );
    assert_eq!(status, 401);
    assert_eq!(unauthorized_credential["error"], "unauthorized");
    let (status, credential) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents/machine-a/control-credential",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(credential["machine_id"], "machine-a");
    assert_eq!(
        credential["control_credential_nonce"],
        first_control_credential_nonce
    );
    assert_eq!(credential["control_secret"], first_control_secret);

    let (status, label_update) = api_request(
        Arc::clone(&app),
        "PATCH",
        "/v1/agents/machine-a/display-name",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"display_name": "Тестовый сервер"}),
    );
    assert_eq!(status, 200);
    assert_eq!(label_update["name"], "server-a");
    assert_eq!(label_update["display_name"], "Тестовый сервер");

    let (status, second_invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);
    let second_token = second_invite["token"]
        .as_str()
        .expect("second invite token")
        .to_owned();
    let mut legacy_reenrollment = enrollment.clone();
    legacy_reenrollment
        .as_object_mut()
        .expect("enrollment object")
        .remove("persistence_mode");
    let (status, reenrolled) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&second_token),
        &legacy_reenrollment,
    );
    assert_eq!(status, 200);
    assert_eq!(reenrolled["id"], agent_id);
    assert_eq!(reenrolled["machine_id"], "machine-a");
    assert_eq!(reenrolled["name"], "server-a");
    let second_control_secret = reenrolled["control_secret"]
        .as_str()
        .expect("second control secret")
        .to_owned();
    assert_ne!(
        first_control_secret, second_control_secret,
        "same-machine re-enrollment must rotate the control credential"
    );
    assert_eq!(reenrolled["remote_port"], remote_port);
    let (status, relisted) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(relisted["agents"][0]["persistence_mode"], "user-session");
    assert_eq!(relisted["agents"][0]["display_name"], "Тестовый сервер");
    assert!(relisted["agents"][0].get("control_secret").is_none());
    let second_control_credential_nonce = relisted["agents"][0]["control_credential_nonce"]
        .as_str()
        .expect("second control credential nonce")
        .to_owned();
    assert_ne!(
        first_control_credential_nonce, second_control_credential_nonce,
        "same-machine re-enrollment must rotate the non-secret credential generation"
    );
    let (status, credential) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents/machine-a/control-credential",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(
        credential["control_credential_nonce"],
        second_control_credential_nonce
    );
    assert_eq!(credential["control_secret"], second_control_secret);

    let (status, reused) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&token),
        &enrollment,
    );
    assert_eq!(status, 401);
    assert_eq!(reused["error"], "invalid_invite");

    let (status, removed) = api_request(
        Arc::clone(&app),
        "DELETE",
        "/v1/agents/machine-a",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(removed["removed"], true);
    let (status, missing_credential) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents/machine-a/control-credential",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 404);
    assert_eq!(missing_credential["error"], "not_found");
    let authorized =
        fs::read_to_string(dir.path().join("authorized_keys")).expect("authorized_keys");
    assert!(!authorized.contains("onec-agent:machine-a"));

    let (status, listed) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(listed["agents"].as_array().map(Vec::len), Some(0));

    let (status, third_invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);
    let third_token = third_invite["token"]
        .as_str()
        .expect("third invite token")
        .to_owned();
    let (status, reenrolled_after_revoke) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&third_token),
        &enrollment,
    );
    assert_eq!(status, 200);
    let third_control_secret = reenrolled_after_revoke["control_secret"]
        .as_str()
        .expect("third control secret");
    assert_ne!(
        third_control_secret, second_control_secret,
        "revoke plus fresh re-enrollment must not resurrect the prior credential"
    );
}

#[test]
fn independent_hub_writers_reload_durable_state_before_mutation() {
    let dir = tempdir().expect("tempdir");
    let mut shared_config = config(dir.path());
    shared_config.probe_gateway_ports_locally = false;
    let app_a = test_app(shared_config.clone());
    let app_b = test_app(shared_config);

    let (status, _) = api_request(
        Arc::clone(&app_a),
        "POST",
        "/v1/invites",
        Some(app_a.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);

    let (status, _) = api_request(
        Arc::clone(&app_b),
        "POST",
        "/v1/invites",
        Some(app_b.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-b"}),
    );
    assert_eq!(status, 201);

    let persisted = HubState::load(&dir.path().join("state.json")).expect("durable state");
    assert_eq!(persisted.invitations.len(), 2);
}

#[test]
fn independent_process_hub_writers_serialize_and_reload_durable_state() {
    use std::process::Command;

    let dir = tempdir().expect("tempdir");
    let go_a = dir.path().join("go-a");
    let go_b = dir.path().join("go-b");
    let ready_a = dir.path().join("ready-a");
    let ready_b = dir.path().join("ready-b");
    let locked_a = dir.path().join("locked-a");
    let attempting_b = dir.path().join("attempting-b");
    let locked_b = dir.path().join("locked-b");
    let release_a = dir.path().join("release-a");
    let executable = env::current_exe().expect("current test executable");

    let mut child_a = Command::new(&executable)
        .arg("--exact")
        .arg("tests::hub_state_mutation_child")
        .arg("--nocapture")
        .env("ONEC_HUB_TEST_WRITER_ROOT", dir.path())
        .env("ONEC_HUB_TEST_WRITER_KEY", "process-a")
        .env("ONEC_HUB_TEST_WRITER_READY", &ready_a)
        .env("ONEC_HUB_TEST_WRITER_GO", &go_a)
        .env("ONEC_HUB_TEST_WRITER_LOCKED", &locked_a)
        .env("ONEC_HUB_TEST_WRITER_RELEASE", &release_a)
        .spawn()
        .expect("spawn writer A");
    wait_for_test_path(&ready_a);
    fs::write(&go_a, b"go").expect("start writer A");
    wait_for_test_path(&locked_a);

    let mut child_b = Command::new(&executable)
        .arg("--exact")
        .arg("tests::hub_state_mutation_child")
        .arg("--nocapture")
        .env("ONEC_HUB_TEST_WRITER_ROOT", dir.path())
        .env("ONEC_HUB_TEST_WRITER_KEY", "process-b")
        .env("ONEC_HUB_TEST_WRITER_READY", &ready_b)
        .env("ONEC_HUB_TEST_WRITER_GO", &go_b)
        .env("ONEC_HUB_TEST_WRITER_ATTEMPTING", &attempting_b)
        .env("ONEC_HUB_TEST_WRITER_LOCKED", &locked_b)
        .spawn()
        .expect("spawn writer B");
    wait_for_test_path(&ready_b);
    fs::write(&go_b, b"go").expect("start writer B");
    wait_for_test_path(&attempting_b);
    assert!(
        !locked_b.exists(),
        "writer B cannot acquire the kernel lock while writer A holds it"
    );

    fs::write(&release_a, b"release").expect("release writer A");
    assert!(child_a.wait().expect("wait writer A").success());
    wait_for_test_path(&locked_b);
    assert!(child_b.wait().expect("wait writer B").success());

    let persisted = HubState::load(&dir.path().join("state.json")).expect("durable state");
    assert!(persisted.invitations.contains_key("process-a"));
    assert!(persisted.invitations.contains_key("process-b"));
}

#[test]
fn hub_reads_observe_state_committed_by_an_independent_writer() {
    let dir = tempdir().expect("tempdir");
    let mut shared_config = config(dir.path());
    shared_config.probe_gateway_ports_locally = false;
    let reader = test_app(shared_config.clone());
    let writer_app = test_app(shared_config);

    let mut writer = writer_app.lock_state_writer().expect("state writer");
    let record = agent_record("machine-a", "cross-process-read", 41000);
    writer
        .state_mut()
        .agents
        .insert(record.machine_id.clone(), record);
    writer.commit(false).expect("commit state");

    let (status, listed) = api_request(
        Arc::clone(&reader),
        "GET",
        "/v1/agents",
        Some(reader.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(listed["agents"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["agents"][0]["machine_id"], "machine-a");
}

#[test]
fn failed_state_publication_does_not_touch_projection() {
    let dir = tempdir().expect("tempdir");
    let app = test_app(config(dir.path()));
    let original_projection = b"unmanaged bytes\n";
    fs::write(&app.config.authorized_keys, original_projection).expect("projection fixture");

    let mut writer = app.lock_state_writer().expect("state writer");
    writer.state_mut().invitations.insert(
        "digest".into(),
        Invitation {
            created_at: 1,
            expires_at: i64::MAX,
            used: false,
            name_hint: None,
        },
    );
    fs::create_dir(&app.config.state_file).expect("block state publication");
    let error = match writer.commit(true) {
        Ok(()) => panic!("state publication must fail"),
        Err(error) => error,
    };
    assert!(!error.committed());
    assert_eq!(
        fs::read(&app.config.authorized_keys).expect("unchanged projection"),
        original_projection
    );
}

#[test]
fn post_commit_projection_failure_keeps_enrollment_and_invite_durable() {
    let dir = tempdir().expect("tempdir");
    let blocker = dir.path().join("projection-parent");
    fs::write(&blocker, b"not-a-directory").expect("projection blocker");

    let mut hub_config = config(dir.path());
    hub_config.authorized_keys = blocker.join("authorized_keys");
    let app = test_app(hub_config);

    let (status, invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);
    let token = invite["token"].as_str().expect("invite token").to_owned();
    let digest = token_digest(&token);

    let enrollment = serde_json::json!({
        "machine_id": "machine-a",
        "name": "server-a",
        "hostname": "SERVER-A",
        "username": "TIS",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.1.0",
        "transport": "open_ssh",
        "persistence_mode": "user-session",
        "ssh_public_key": key("projection-failure"),
        "ssh_host_public_key": key("projection-failure-host"),
    });
    let (status, response) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&token),
        &enrollment,
    );
    assert_eq!(status, 503);
    assert_eq!(response["error"], "reconciliation_required");

    let persisted = HubState::load(&app.config.state_file).expect("committed hub state");
    assert!(persisted.agents.contains_key("machine-a"));
    assert!(
        persisted
            .invitations
            .get(&digest)
            .is_some_and(|invite| invite.used)
    );
    let reloaded = HubState::load(&app.config.state_file).expect("reloaded committed hub state");
    assert!(reloaded.agents.contains_key("machine-a"));

    fs::remove_file(&blocker).expect("remove projection blocker");
    fs::create_dir(&blocker).expect("projection parent");
    prepare_server_state(&app).expect("startup reconciliation");
    let authorized = fs::read_to_string(&app.config.authorized_keys).expect("authorized_keys");
    assert!(authorized.contains("onec-agent:machine-a"));
}

#[test]
fn serve_reconciles_projection_before_listener_becomes_healthy() {
    use std::process::Command;

    let dir = tempdir().expect("tempdir");
    let hub_config = config(dir.path());
    let mut state = HubState::default();
    let current = agent_record("machine-current", "current", 41000);
    state
        .agents
        .insert(current.machine_id.clone(), current.clone());
    state
        .save(&hub_config.state_file)
        .expect("authoritative state");

    let stale = agent_record("machine-stale", "stale", 41001);
    let mut projection = b"# unmanaged\r\n".to_vec();
    projection.extend_from_slice(
        authorized_key_line(&stale)
            .expect("stale managed key")
            .as_bytes(),
    );
    projection.push(b'\n');
    fs::write(&hub_config.authorized_keys, &projection).expect("stale projection");

    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve serve address");
    let address = reservation.local_addr().expect("serve address");
    drop(reservation);

    let executable = env::current_exe().expect("current test executable");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("tests::hub_serve_startup_child")
        .arg("--nocapture")
        .env("ONEC_HUB_TEST_SERVE_ROOT", dir.path())
        .env("ONEC_HUB_TEST_SERVE_LISTEN", address.to_string())
        .spawn()
        .expect("spawn serve child");

    if !wait_for_hub_health(address, Duration::from_secs(5)) {
        let _ = child.kill();
        let status = child.wait().expect("wait failed serve child");
        panic!("serve child never became healthy: {status}");
    }
    child.kill().expect("stop serve child");
    let _ = child.wait().expect("wait serve child");

    let reconciled = fs::read(&hub_config.authorized_keys).expect("reconciled projection");
    assert!(reconciled.starts_with(b"# unmanaged\r\n"));
    let text = String::from_utf8(reconciled).expect("managed projection UTF-8");
    assert!(text.contains("onec-agent:machine-current"));
    assert!(!text.contains("onec-agent:machine-stale"));
}

#[test]
fn hub_state_writer_honors_exclusive_sidecar_lock_across_processes() {
    use std::process::Command;

    let dir = tempdir().expect("tempdir");
    let ready = dir.path().join("lock-ready");
    let executable = env::current_exe().expect("current test executable");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("tests::hub_state_lock_holder_child")
        .arg("--nocapture")
        .env("ONEC_HUB_TEST_LOCK_ROOT", dir.path())
        .env("ONEC_HUB_TEST_LOCK_READY", &ready)
        .spawn()
        .expect("spawn lock holder");
    wait_for_test_path(&ready);

    let mut hub_config = config(dir.path());
    hub_config.probe_gateway_ports_locally = false;
    let app = test_app(hub_config);
    let error =
        match app.lock_state_writer_for_test(Duration::from_millis(40), Duration::from_millis(5)) {
            Ok(_) => panic!("second process must not bypass state lock"),
            Err(error) => error,
        };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);

    child.kill().expect("kill lock holder");
    let _ = child.wait().expect("wait lock holder");
    app.lock_state_writer_for_test(Duration::from_secs(1), Duration::from_millis(5))
        .expect("process death must release state lock");
}

#[test]
fn regression_inv_061_enrollment_rejects_unknown_persistence_mode() {
    let input = EnrollRequest {
        machine_id: "machine-a".into(),
        name: "server-a".into(),
        hostname: "SERVER-A".into(),
        username: Some("EXAMPLE\\svc".into()),
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: Some("magic-daemon".into()),
        ssh_public_key: key("api"),
        ssh_host_public_key: None,
    };
    let error = validate_enrollment(&input).expect_err("unknown persistence mode");
    assert!(error.to_string().contains("persistence_mode"));
}

#[test]
fn port_allocation_is_stable_and_collision_free() {
    let dir = tempdir().expect("tempdir");
    let mut config = config(dir.path());
    config.reserved_ports = vec![41000];
    let mut state = HubState::default();
    assert_eq!(
        allocate_port_with_probe(&state, &config, |_| Ok(true)).expect("port"),
        41001
    );
    state.agents.insert(
        "machine-a".into(),
        AgentRecord {
            id: "id-a".into(),
            machine_id: "machine-a".into(),
            name: "a".into(),
            display_name: None,
            hostname: "a".into(),
            username: None,
            os: "windows".into(),
            arch: "x86_64".into(),
            agent_version: "0.1.0".into(),
            transport: "open_ssh".into(),
            persistence_mode: None,
            remote_port: 41001,
            ssh_public_key: key("a"),
            ssh_host_public_key: None,
            control_credential_nonce: None,
            enrolled_at: 1,
            updated_at: 1,
        },
    );
    assert_eq!(
        allocate_port_with_probe(&state, &config, |port| Ok(port != 41002))
            .expect_err("externally occupied final port must exhaust pool")
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );

    config.port_to = 41003;
    assert_eq!(
        allocate_port_with_probe(&state, &config, |port| Ok(port != 41002))
            .expect("skip externally occupied port"),
        41003
    );
}

#[test]
fn hub_authority_can_authorize_edge_ssh_without_local_gateway_files() {
    let mut state = HubState::default();
    let record = AgentRecord {
        id: "id-edge".into(),
        machine_id: "machine-edge".into(),
        name: "server-edge".into(),
        display_name: None,
        hostname: "SERVER-EDGE".into(),
        username: None,
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: None,
        remote_port: 41002,
        ssh_public_key: key("edge"),
        ssh_host_public_key: None,
        control_credential_nonce: None,
        enrolled_at: 1,
        updated_at: 1,
    };
    state
        .agents
        .insert(record.machine_id.clone(), record.clone());
    let normalized = normalize_public_key(&record.ssh_public_key).expect("normalized key");
    let mut parts = normalized.split_whitespace();
    let key_type = parts.next().expect("key type");
    let key_blob = parts.next().expect("key blob");
    let line = lookup_authorized_key(&state, key_type, key_blob)
        .expect("lookup")
        .expect("enrolled key");
    assert!(line.contains("permitlisten=\"127.0.0.1:41002\""));
    assert!(line.contains("onec-agent:machine-edge"));
    let unknown = normalize_public_key(&key("unknown")).expect("unknown normalized key");
    let unknown_blob = unknown.split_whitespace().nth(1).expect("unknown key blob");
    assert!(
        lookup_authorized_key(&state, key_type, unknown_blob)
            .expect("unknown lookup")
            .is_none()
    );
    assert!(lookup_authorized_key(&state, "ssh-rsa", key_blob).is_err());
}

#[test]
fn split_mode_does_not_create_local_authorized_keys_projection() {
    let dir = tempdir().expect("tempdir");
    let mut split_config = config(dir.path());
    split_config.probe_gateway_ports_locally = false;
    let app = Arc::new(App {
        config: split_config,
        operator_token: "operator-token-0123456789abcdef".into(),
        agent_secret_key: "agent-master-key-0123456789abcdef".into(),
        ssh_lookup_token: Some("lookup-token-0123456789abcdef".into()),
        state_writer: Mutex::new(()),
    });

    let (status, invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-split"}),
    );
    assert_eq!(status, 201);
    let token = invite["token"].as_str().expect("invite token").to_owned();
    let (status, _) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(&token),
        &serde_json::json!({
            "machine_id": "machine-split",
            "name": "server-split",
            "hostname": "SERVER-SPLIT",
            "os": "windows",
            "arch": "x86_64",
            "agent_version": "0.1.0",
            "transport": "open_ssh",
            "ssh_public_key": key("split"),
        }),
    );
    assert_eq!(status, 200);
    assert!(!dir.path().join("authorized_keys").exists());

    let (status, removed) = api_request(
        Arc::clone(&app),
        "DELETE",
        "/v1/agents/machine-split",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(removed["removed"], true);
    assert!(!dir.path().join("authorized_keys").exists());
}

#[test]
fn hub_authority_can_disable_local_gateway_port_probe() {
    let dir = tempdir().expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0").expect("occupied local port");
    let occupied = listener.local_addr().expect("local address").port();
    let mut config = config(dir.path());
    config.port_from = occupied;
    config.port_to = occupied;
    config.probe_gateway_ports_locally = false;
    assert_eq!(
        allocate_port(&HubState::default(), &config).expect("remote-only allocation"),
        occupied
    );
    config.probe_gateway_ports_locally = true;
    assert_eq!(
        allocate_port(&HubState::default(), &config)
            .expect_err("local probe sees occupied port")
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    drop(listener);
}

#[test]
fn authorized_keys_replaces_only_same_machine_entry() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("authorized_keys");
    fs::write(&path, "ssh-ed25519 AAAA unrelated\n").expect("fixture");
    let record = AgentRecord {
        id: "id-a".into(),
        machine_id: "machine-a".into(),
        name: "server-a".into(),
        display_name: None,
        hostname: "server-a".into(),
        username: None,
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: None,
        remote_port: 41001,
        ssh_public_key: key("first"),
        ssh_host_public_key: None,
        control_credential_nonce: None,
        enrolled_at: 1,
        updated_at: 1,
    };
    let mut state = HubState::default();
    state
        .agents
        .insert(record.machine_id.clone(), record.clone());
    reconcile_authorized_keys(&path, &state).expect("first projection");
    let mut changed = record.clone();
    changed.ssh_public_key = key("second");
    state
        .agents
        .insert(changed.machine_id.clone(), changed.clone());
    reconcile_authorized_keys(&path, &state).expect("replace projection");
    let text = fs::read_to_string(&path).expect("authorized_keys");
    assert_eq!(text.matches("onec-agent:machine-a").count(), 1);
    assert!(text.contains("unrelated"));
    assert!(text.contains("permitlisten=\"127.0.0.1:41001\""));
    assert!(text.contains("command=\"/bin/false\""));

    state.agents.remove("machine-a");
    reconcile_authorized_keys(&path, &state).expect("revoke projection");
    let text = fs::read_to_string(path).expect("authorized_keys after revoke");
    assert!(text.contains("unrelated"));
    assert!(!text.contains("onec-agent:machine-a"));
}

#[test]
fn authorized_keys_reconciliation_repairs_reserved_namespace_deterministically() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("authorized_keys");
    let stale = agent_record("machine-stale", "stale", 41990);
    let old_b = agent_record("machine-b", "old-b", 41991);

    let mut existing = b"# unmanaged\r\nraw-\xff-bytes\nmalformed onec-agent:keep-me\n".to_vec();
    existing.extend_from_slice(authorized_key_line(&stale).expect("stale line").as_bytes());
    existing.push(b'\n');
    existing.extend_from_slice(authorized_key_line(&old_b).expect("old b line").as_bytes());
    existing.push(b'\n');
    fs::write(&path, &existing).expect("authorized_keys fixture");

    let mut state = HubState::default();
    let a = agent_record("machine-a", "a", 41000);
    let b = agent_record("machine-b", "b", 41001);
    state.agents.insert(b.machine_id.clone(), b.clone());
    state.agents.insert(a.machine_id.clone(), a.clone());

    reconcile_authorized_keys(&path, &state).expect("reconcile projection");
    let reconciled = fs::read(&path).expect("reconciled authorized_keys");
    let unmanaged = b"# unmanaged\r\nraw-\xff-bytes\nmalformed onec-agent:keep-me\n";
    assert!(reconciled.starts_with(unmanaged));
    let managed = std::str::from_utf8(&reconciled[unmanaged.len()..]).expect("managed utf8");
    assert!(!managed.contains("onec-agent:machine-stale"));
    assert_eq!(managed.matches("onec-agent:machine-a").count(), 1);
    assert_eq!(managed.matches("onec-agent:machine-b").count(), 1);
    assert!(
        managed.find("onec-agent:machine-a").expect("machine-a")
            < managed.find("onec-agent:machine-b").expect("machine-b")
    );
    assert!(managed.contains(&normalize_public_key(&a.ssh_public_key).expect("a key")));
    assert!(managed.contains(&normalize_public_key(&b.ssh_public_key).expect("b key")));
    assert!(!managed.contains(&normalize_public_key(&old_b.ssh_public_key).expect("old b key")));
}

#[test]
fn assigned_names_skip_suffix_collisions_case_insensitively() {
    let mut state = HubState::default();
    let mut base = agent_record("machine-a", "a", 41000);
    base.name = "SERVER".into();
    state.agents.insert(base.machine_id.clone(), base);
    let mut first_suffix = agent_record("12345678-other", "b", 41001);
    first_suffix.name = "server-12345678".into();
    state
        .agents
        .insert(first_suffix.machine_id.clone(), first_suffix);
    let mut second_suffix = agent_record("machine-c", "c", 41002);
    second_suffix.name = "SERVER-12345678-2".into();
    state
        .agents
        .insert(second_suffix.machine_id.clone(), second_suffix);

    assert_eq!(
        assign_name(&state, "12345678-abcd", "server").expect("unique name"),
        "server-12345678-3"
    );
}

#[test]
fn assigned_name_ignores_current_machine_and_resolves_machine_prefix_collisions() {
    let mut state = HubState::default();
    let mut base = agent_record("machine-base", "base", 41001);
    base.name = "SERVER".into();
    state.agents.insert(base.machine_id.clone(), base);
    let mut current = agent_record("12345678-current", "current", 41000);
    current.name = "SERVER-12345678".into();
    state.agents.insert(current.machine_id.clone(), current);

    assert_eq!(
        assign_name(&state, "12345678-current", "server-12345678").expect("same-machine name"),
        "server-12345678"
    );
    assert_eq!(
        assign_name(&state, "12345678-next", "SERVER").expect("unique prefixed name"),
        "SERVER-12345678-2"
    );
}

#[test]
fn assigned_name_stays_within_identifier_length_and_character_contract() {
    let mut state = HubState::default();
    let mut occupied = agent_record("machine-a", "a", 41000);
    occupied.name = "a".repeat(128);
    state.agents.insert(occupied.machine_id.clone(), occupied);

    let assigned = assign_name(&state, "machine-b", &"a".repeat(128)).expect("unique name");
    assert!(assigned.len() <= 128);
    assert!(validate_identifier("name", &assigned, 128).is_ok());
    assert_eq!(assigned.len(), 128);
}

#[test]
fn enrollment_identifiers_require_canonical_whitespace() {
    for value in ["machine-1", "server_2.example", "a"] {
        assert!(validate_machine_id(value).is_ok());
        assert!(validate_identifier("name", value, 128).is_ok());
    }
    for value in [" machine-1", "machine-1 ", "\tmachine-1", "machine-1\n"] {
        assert!(validate_machine_id(value).is_err());
        assert!(validate_identifier("name", value, 128).is_err());
    }
    assert!(validate_machine_id("Machine-1").is_err());
    assert!(validate_identifier("name", "SERVER_2.example", 128).is_ok());
}

#[test]
fn enrollment_with_noncanonical_machine_id_does_not_consume_invite_or_create_identity() {
    let dir = tempdir().expect("tempdir");
    let mut hub_config = config(dir.path());
    hub_config.probe_gateway_ports_locally = false;
    let app = test_app(hub_config);
    let (status, invite) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/invites",
        Some(app.operator_token.expose_secret()),
        &serde_json::json!({"ttl_seconds": 900, "name": "server-a"}),
    );
    assert_eq!(status, 201);
    let token = invite["token"].as_str().expect("invite token");
    let state_before_rejected_enrollment =
        fs::read(dir.path().join("state.json")).expect("persisted invitation state");
    let mut enrollment = serde_json::json!({
        "machine_id": " machine-a",
        "name": "ignored-name",
        "hostname": "SERVER-A",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.1.0",
        "transport": "open_ssh",
        "ssh_public_key": key("canonical-id"),
    });
    let (status, rejected) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(token),
        &enrollment,
    );
    assert_eq!(status, 400);
    assert_eq!(rejected["error"], "bad_request");
    assert_eq!(
        fs::read(dir.path().join("state.json")).expect("state after rejected enrollment"),
        state_before_rejected_enrollment
    );

    enrollment["machine_id"] = serde_json::json!("machine-a");
    let (status, accepted) = api_request(
        Arc::clone(&app),
        "POST",
        "/v1/enroll",
        Some(token),
        &enrollment,
    );
    assert_eq!(status, 200);
    assert_eq!(accepted["machine_id"], "machine-a");

    let (status, rejected_lookup) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents/Machine-a/control-credential",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 400);
    assert_eq!(rejected_lookup["error"], "bad_request");
    let (status, rejected_removal) = api_request(
        Arc::clone(&app),
        "DELETE",
        "/v1/agents/%20machine-a",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 400);
    assert_eq!(rejected_removal["error"], "bad_request");
    let (status, inventory) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(inventory["agents"].as_array().map(Vec::len), Some(1));
    assert_eq!(inventory["agents"][0]["machine_id"], "machine-a");
}

#[test]
fn same_machine_reenrollment_preserves_record_identity_name_and_port() {
    let dir = tempdir().expect("tempdir");
    let mut hub_config = config(dir.path());
    hub_config.probe_gateway_ports_locally = false;
    let app = test_app(hub_config);
    let enrollment = serde_json::json!({
        "machine_id": "machine-a",
        "name": "client-name",
        "hostname": "SERVER-A",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.1.0",
        "transport": "open_ssh",
        "ssh_public_key": key("reenrollment"),
    });

    let enroll_with_fresh_invite = || {
        let (status, invite) = api_request(
            Arc::clone(&app),
            "POST",
            "/v1/invites",
            Some(app.operator_token.expose_secret()),
            &serde_json::json!({"ttl_seconds": 900, "name": "Server-A"}),
        );
        assert_eq!(status, 201);
        let token = invite["token"].as_str().expect("invite token");
        let (status, response) = api_request(
            Arc::clone(&app),
            "POST",
            "/v1/enroll",
            Some(token),
            &enrollment,
        );
        assert_eq!(status, 200);
        response
    };

    let first = enroll_with_fresh_invite();
    let (status, first_inventory) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    let first_nonce = first_inventory["agents"][0]["control_credential_nonce"].clone();
    let second = enroll_with_fresh_invite();
    let (status, second_inventory) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(app.operator_token.expose_secret()),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(first["id"], second["id"]);
    assert_eq!(first["machine_id"], second["machine_id"]);
    assert_eq!(first["name"], "Server-A");
    assert_eq!(first["name"], second["name"]);
    assert_eq!(first["remote_port"], second["remote_port"]);
    assert_ne!(
        first_nonce,
        second_inventory["agents"][0]["control_credential_nonce"]
    );
    assert_ne!(
        first["control_secret"], second["control_secret"],
        "fresh same-machine enrollment rotates its credential generation"
    );
}

#[test]
fn enrollment_public_key_must_be_structurally_valid_ed25519_single_line() {
    let original = key("fixture");
    let normalized = normalize_public_key(&original).expect("valid fixture key");
    assert!(normalized.starts_with("ssh-ed25519 "));
    assert!(!normalized.contains("fixture-fixture"));
    assert!(normalize_public_key("ssh-ed25519 !!!not-base64!!!").is_err());
    assert!(normalize_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5").is_err());
    assert!(normalize_public_key("ssh-rsa AAAABBBB").is_err());
    assert!(normalize_public_key("ssh-ed25519 AAAA\nssh-ed25519 BBBB").is_err());
}

#[test]
fn config_rejects_malformed_gateway_host_key() {
    let dir = tempdir().expect("tempdir");
    let mut config = config(dir.path());
    config.gateways[0].host_public_key = "ssh-ed25519 !!!not-base64!!!".into();
    assert!(config.validate().is_err());
}

#[test]
fn operator_key_identity_ignores_comments_when_rejecting_duplicates() {
    let dir = tempdir().expect("tempdir");
    let mut config = config(dir.path());
    let first = key("same-key");
    let normalized = normalize_public_key(&first).expect("normalize same key");
    config.operator_ssh_public_key = first.clone();
    config.operator_ssh_public_keys = vec![
        first,
        format!("{normalized} a completely different comment"),
    ];
    assert!(config.validate().is_err());
}

#[test]
fn display_label_patch_is_authenticated_validated_and_identity_preserving() {
    let dir = tempdir().expect("tempdir");
    let app = test_app(config(dir.path()));
    let mut state = HubState::default();
    state.agents.insert(
        "machine-test".into(),
        agent_record("machine-test", "fixture", 41000),
    );
    state.save(&app.config.state_file).expect("initial state");

    let path = "/v1/agents/machine-test/display-name";
    let token = app.operator_token.expose_secret();
    let original = HubState::load(&app.config.state_file)
        .expect("initial read")
        .agents
        .get("machine-test")
        .expect("fixture")
        .clone();

    for (auth, path, body, expected) in [
        (
            None,
            path,
            serde_json::json!({"display_name":"Тестовый сервер"}),
            401,
        ),
        (
            Some(token),
            "/v1/agents/unknown/display-name",
            serde_json::json!({"display_name":"Other"}),
            404,
        ),
        (Some(token), path, serde_json::json!({}), 400),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":13}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":""}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":" \t "}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":"a\nb"}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":"x\u{202e}y"}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":"x".repeat(129)}),
            400,
        ),
        (
            Some(token),
            path,
            serde_json::json!({"display_name":"good", "ignored":"extra"}),
            400,
        ),
    ] {
        let (status, _) = api_request(Arc::clone(&app), "PATCH", path, auth, &body);
        assert_eq!(status, expected, "invalid patch request: {body:?}");
        let actual = HubState::load(&app.config.state_file)
            .expect("read after rejection")
            .agents
            .get("machine-test")
            .expect("fixture remains")
            .clone();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&original).unwrap(),
            "invalid patch must not mutate hub state"
        );
    }

    let (status, updated) = api_request(
        Arc::clone(&app),
        "PATCH",
        path,
        Some(token),
        &serde_json::json!({"display_name": "  Тестовый сервер  "}),
    );
    assert_eq!(status, 200);
    assert_eq!(updated["name"], "machine-test");
    assert_eq!(updated["display_name"], "Тестовый сервер");
    let after = HubState::load(&app.config.state_file).expect("persistent state");
    let agent = after.agents.get("machine-test").expect("agent");
    assert_eq!(agent.display_name.as_deref(), Some("Тестовый сервер"));
    let mut before_label = agent.clone();
    before_label.display_name = None;
    assert_eq!(
        serde_json::to_value(&before_label).unwrap(),
        serde_json::to_value(&original).unwrap(),
        "display update must not rotate keys, identity, or time stamps"
    );

    let (status, inventory) = api_request(
        Arc::clone(&app),
        "GET",
        "/v1/agents",
        Some(token),
        &serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(inventory["agents"][0]["name"], "machine-test");
    assert_eq!(inventory["agents"][0]["display_name"], "Тестовый сервер");
    assert!(inventory["agents"][0].get("control_secret").is_none());

    let (status, cleared) = api_request(
        Arc::clone(&app),
        "PATCH",
        path,
        Some(token),
        &serde_json::json!({"display_name":null}),
    );
    assert_eq!(status, 200);
    assert!(cleared["display_name"].is_null());
    let state = HubState::load(&app.config.state_file).expect("after clear");
    assert_eq!(
        serde_json::to_value(state.agents.get("machine-test").unwrap()).unwrap(),
        serde_json::to_value(original).unwrap()
    );
}
