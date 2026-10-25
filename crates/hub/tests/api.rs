use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hostlink_hub::{
    EnrollRequest, GatewayEndpoint, HubConfig, HubService, InviteRequest, MachineId, router,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};
use tower::ServiceExt;

const OPERATOR: &str = "operator-token-for-test-0123456789-abcdef";
const EDGE: &str = "gateway-token-for-test-0123456789-abcdef";

fn key() -> String {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source");
    let private: ssh_key::PrivateKey = ssh_key::private::Ed25519Keypair::from_seed(&seed).into();
    private
        .public_key()
        .to_openssh()
        .expect("encode public key")
}
fn service(root: &std::path::Path, gateway_key: String) -> HubService {
    service_with_keys(
        root,
        gateway_key,
        root.join("gateway/hostlink-v2-authorized_keys"),
    )
}
fn service_with_keys(
    root: &std::path::Path,
    gateway_key: String,
    authorized_keys: PathBuf,
) -> HubService {
    let state_root = root.join("hostlink-hub-v2");
    HubService::new(HubConfig {
        listen: "127.0.0.1:27400".parse::<SocketAddr>().unwrap(),
        public_url: "https://hub.test".into(),
        state_root,
        authorized_keys,
        gateways: vec![GatewayEndpoint {
            host: "gateway.test".into(),
            user: "hostlink-gateway".into(),
            port: 22,
            host_public_key: gateway_key,
        }],
        operator_ssh_public_keys: vec![key()],
        operator_token: OPERATOR.into(),
        gateway_lookup_token: EDGE.into(),
        port_from: 41000,
        port_to: 41010,
        reserved_ports: BTreeSet::from([41000]),
    })
    .expect("valid test Hub")
}
async fn call(
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn call_raw(
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn invite(app: axum::Router, name: &str, rotate: Option<&str>) -> String {
    let request = InviteRequest {
        ttl_seconds: 900,
        name: Some(name.into()),
        rotate_machine_id: rotate.map(|id| MachineId::parse(id).unwrap()),
    };
    let (status, response) = call(
        app,
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        serde_json::to_value(request).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    response["token"].as_str().unwrap().to_owned()
}
fn enrollment(
    token: String,
    id: &str,
    name: &str,
    reverse_key: String,
    host_key: String,
) -> EnrollRequest {
    EnrollRequest {
        token: SecretString::from(token),
        machine_id: MachineId::parse(id).unwrap(),
        name: name.into(),
        hostname: "fixture".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        ssh_public_key: reverse_key,
        ssh_host_public_key: host_key,
    }
}

#[tokio::test]
async fn invite_enroll_inventory_rename_revoke_and_restart_are_secret_free() {
    let dir = tempfile::tempdir().unwrap();
    let reverse = key();
    let host_key = key();
    let gateway = key();
    let managed = format!(
        "ssh-ed25519 {} onec-agent:legacy-must-survive",
        reverse.split_whitespace().nth(1).unwrap()
    );
    std::fs::create_dir_all(dir.path().join("gateway")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("gateway"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join("gateway/hostlink-v2-authorized_keys"),
        format!("{managed}\n# operator entry\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("gateway/hostlink-v2-authorized_keys"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let app = router(service(dir.path(), gateway.clone()));
    let (health_status, health) = call(app.clone(), "GET", "/healthz", None, json!({})).await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["status"], "ok");
    let (info_status, info) = call(app.clone(), "GET", "/v2/info", Some(OPERATOR), json!({})).await;
    assert_eq!(info_status, StatusCode::OK);
    assert_eq!(info["api_version"], 2);
    assert_eq!(info["execution_transport"], "russh");
    let (status, _) = call(app.clone(), "GET", "/v2/hosts", None, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let token = invite(app.clone(), "lab-win7", None).await;
    let (status, enrolled) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token.clone(),
            "machine-001",
            "lab-win7",
            reverse.clone(),
            host_key,
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let host = &enrolled["host"];
    assert_eq!(host["machine_id"], "machine-001");
    assert_ne!(host["remote_port"], 41000);
    assert_eq!(enrolled["gateways"][0]["host_public_key"], gateway);
    let state =
        std::fs::read_to_string(dir.path().join("hostlink-hub-v2/registry-v2.json")).unwrap();
    assert!(!state.contains(&token));
    let projected =
        std::fs::read_to_string(dir.path().join("gateway/hostlink-v2-authorized_keys")).unwrap();
    assert!(projected.contains("hostlink-agent:machine-001"));
    assert!(projected.contains("onec-agent:legacy-must-survive"));
    let (status, list) = call(app.clone(), "GET", "/v2/hosts", Some(OPERATOR), json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["hosts"].as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(&token));
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "machine-001",
            "lab-win7",
            reverse.clone(),
            key(),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, renamed) = call(
        app.clone(),
        "PATCH",
        "/v2/hosts/machine-001/display-name",
        Some(OPERATOR),
        json!({"display_name":"Lab workstation"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["machine_id"], "machine-001");
    assert_eq!(renamed["display_name"], "Lab workstation");
    let parts: Vec<_> = reverse.split_whitespace().collect();
    let (status, lookup) = call(
        app.clone(),
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":parts[0],"key_blob":parts[1]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], true);
    assert!(
        lookup["authorized_key"]
            .as_str()
            .unwrap()
            .contains(&format!(
                "permitlisten=\"127.0.0.1:{}\"",
                host["remote_port"].as_u64().unwrap()
            ))
    );
    let (status, receipt) = call(
        app.clone(),
        "DELETE",
        "/v2/hosts/machine-001",
        Some(OPERATOR),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["revoked_new_connections"], true);
    assert_eq!(receipt["confirmed_session_terminated"], false);
    assert_eq!(receipt["remote_uninstall"], false);
    assert_eq!(receipt["authorized_key_projection"], "reconciled");
    let (status, _) = call(
        app.clone(),
        "DELETE",
        "/v2/hosts/machine-001",
        Some(OPERATOR),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, lookup) = call(
        app.clone(),
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":parts[0],"key_blob":parts[1]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], false);
    let unknown = key();
    let unknown_parts: Vec<_> = unknown.split_whitespace().collect();
    let (status, lookup) = call(
        app.clone(),
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":unknown_parts[0],"key_blob":unknown_parts[1]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], false);
    let projected =
        std::fs::read_to_string(dir.path().join("gateway/hostlink-v2-authorized_keys")).unwrap();
    assert!(!projected.contains("hostlink-agent:machine-001"));
    assert!(projected.contains("onec-agent:legacy-must-survive"));
    assert!(projected.contains("# operator entry"));
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("hostlink-hub-v2/registry-v2.json")).unwrap(),
    )
    .unwrap();
    let actions: Vec<_> = persisted["audit"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(actions.contains(&"enrolled"));
    assert!(actions.contains(&"rename"));
    assert!(actions.contains(&"revoke"));
    let restarted = router(service(dir.path(), key()));
    let (status, list) = call(restarted, "GET", "/v2/hosts", Some(OPERATOR), json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["hosts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn projection_failure_is_reported_after_authoritative_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("gateway/hostlink-v2-authorized_keys");
    std::fs::create_dir_all(&key_path).unwrap();
    let reverse = key();
    let host = key();
    let parts: Vec<_> = reverse.split_whitespace().collect();
    let app = router(service_with_keys(dir.path(), key(), key_path));
    let token = invite(app.clone(), "node", None).await;
    let (status, body) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "machine-reconcile",
            "node",
            reverse.clone(),
            host,
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["message"].as_str().unwrap().contains("committed"));
    let (status, lookup) = call(
        app.clone(),
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":parts[0],"key_blob":parts[1]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], true);
    let (status, receipt) = call(
        app.clone(),
        "DELETE",
        "/v2/hosts/machine-reconcile",
        Some(OPERATOR),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(receipt["error"], "reconciliation_required");
    assert!(receipt["message"].as_str().unwrap().contains("committed"));
    let (status, lookup) = call(
        app,
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":parts[0],"key_blob":parts[1]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], false);
}

#[tokio::test]
async fn assigned_routes_are_unique_and_reserved_ports_are_never_used() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let mut assigned = std::collections::BTreeSet::new();
    for id in ["route-a", "route-b", "route-c"] {
        let name = id;
        let token = invite(app.clone(), name, None).await;
        let (status, result) = call(
            app.clone(),
            "POST",
            "/v2/enroll",
            None,
            serde_json::to_value(enrollment(token, id, name, key(), key())).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let port = result["host"]["remote_port"].as_u64().unwrap() as u16;
        assert_ne!(port, 41000);
        assert!(assigned.insert(port));
    }
}

#[tokio::test]
async fn expiry_duplicate_name_and_parallel_fresh_invites_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let expired = invite(app.clone(), "expired", None).await;
    let state_path = dir.path().join("hostlink-hub-v2/registry-v2.json");
    let mut state: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    for entry in state["invites"].as_object_mut().unwrap().values_mut() {
        entry["expires_at"] = json!(0);
    }
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(expired, "expired-node", "expired", key(), key())).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let first = invite(app.clone(), "shared-name", None).await;
    let second = invite(app.clone(), "shared-name", None).await;
    let first_request = serde_json::to_value(enrollment(
        first,
        "parallel-node",
        "shared-name",
        key(),
        key(),
    ))
    .unwrap();
    let second_request = serde_json::to_value(enrollment(
        second,
        "parallel-node",
        "shared-name",
        key(),
        key(),
    ))
    .unwrap();
    let (left, right) = tokio::join!(
        call(app.clone(), "POST", "/v2/enroll", None, first_request),
        call(app.clone(), "POST", "/v2/enroll", None, second_request)
    );
    let statuses = [left.0, right.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count(),
        1
    );
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        json!({"ttl_seconds":900,"name":"shared-name"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn fresh_invite_cannot_hijack_and_rotation_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let original = key();
    let host = key();
    let token = invite(app.clone(), "node", None).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "machine-002",
            "node",
            original.clone(),
            host,
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let takeover = invite(app.clone(), "other", None).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(takeover, "machine-002", "other", key(), key())).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let rotation = invite(app.clone(), "node", Some("machine-002")).await;
    let replacement = key();
    let (status, response) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            rotation,
            "machine-002",
            "node",
            replacement.clone(),
            key(),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(response["host"]["ssh_public_key"], replacement);
}

#[tokio::test]
async fn malformed_reused_or_unknown_invites_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/invites",
        Some("wrong"),
        json!({"ttl_seconds":900}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        json!({"ttl_seconds":900,"unexpected":true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let(status,_)=call(app.clone(),"POST","/v2/enroll",None,json!({"token":"unknown","machine_id":"machine","name":"n","hostname":"h","os":"linux","arch":"x86_64","agent_version":"0.1","ssh_public_key":"bad"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let token = invite(app.clone(), "node", None).await;
    let reverse = key();
    let host = key();
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "machine-003",
            "node",
            reverse.clone(),
            host.clone(),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let fresh = invite(app.clone(), "duplicate", None).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            fresh,
            "machine-004",
            "duplicate",
            reverse,
            key(),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn same_underlying_ed25519_key_cannot_fill_both_agent_roles() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let token = invite(app.clone(), "node", None).await;
    let same = key();
    let reverse = format!("{same} reverse");
    let host = format!("{same} host");
    let (status, _) = call(
        app,
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(token, "machine-roles", "node", reverse, host)).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_http_and_truncated_persistent_state_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let (status, _) = call_raw(
        app.clone(),
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        "{not-json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let path = dir.path().join("hostlink-hub-v2/registry-v2.json");
    std::fs::write(&path, b"{truncated").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (status, body) = call(app, "GET", "/v2/hosts", Some(OPERATOR), json!({})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["message"], "request failed");
}

#[test]
fn state_root_symlink_and_namespace_collision_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let actual = dir.path().join("hostlink-hub-v2");
    std::fs::create_dir(&actual).unwrap();
    #[cfg(unix)]
    {
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        let config = HubConfig {
            listen: "127.0.0.1:27400".parse().unwrap(),
            public_url: "https://hub.test".into(),
            state_root: alias,
            authorized_keys: PathBuf::from("hostlink-v2-authorized_keys"),
            gateways: vec![],
            operator_ssh_public_keys: vec![],
            operator_token: OPERATOR.into(),
            gateway_lookup_token: EDGE.into(),
            port_from: 41000,
            port_to: 41010,
            reserved_ports: BTreeSet::new(),
        };
        assert!(HubService::new(config).is_err());
    }
    let config = HubConfig {
        listen: "0.0.0.0:27400".parse().unwrap(),
        public_url: "https://hub.test".into(),
        state_root: actual,
        authorized_keys: PathBuf::from("hostlink-v2-authorized_keys"),
        gateways: vec![],
        operator_ssh_public_keys: vec![],
        operator_token: OPERATOR.into(),
        gateway_lookup_token: EDGE.into(),
        port_from: 41000,
        port_to: 41010,
        reserved_ports: BTreeSet::new(),
    };
    assert!(HubService::new(config).is_err());

    let bad_pin = HubConfig {
        listen: "127.0.0.1:27400".parse().unwrap(),
        public_url: "https://hub.test".into(),
        state_root: dir.path().join("bad-pin/hostlink-hub-v2"),
        authorized_keys: dir.path().join("hostlink-v2-authorized_keys"),
        gateways: vec![GatewayEndpoint {
            host: "gateway.test".into(),
            user: "gateway".into(),
            port: 22,
            host_public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==".into(),
        }],
        operator_ssh_public_keys: vec![key()],
        operator_token: OPERATOR.into(),
        gateway_lookup_token: EDGE.into(),
        port_from: 41000,
        port_to: 41010,
        reserved_ports: BTreeSet::new(),
    };
    assert!(HubService::new(bad_pin).is_err());
}

#[test]
fn hub_public_url_rejects_credentials_paths_queries_fragments_and_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let gateway_key = key();
    let operator_key = key();
    for (index, invalid_url) in [
        "http://hub.example.test",
        "https://user@hub.example.test",
        "https://hub.example.test/prefix",
        "https://hub.example.test?token=secret",
        "https://hub.example.test/#fragment",
        "https://",
        "https://hub.example.test:invalid",
    ]
    .into_iter()
    .enumerate()
    {
        let root = dir.path().join(format!("{index}/hostlink-hub-v2"));
        let config = HubConfig {
            listen: "127.0.0.1:27400".parse().unwrap(),
            public_url: invalid_url.to_owned(),
            state_root: root.clone(),
            authorized_keys: dir.path().join("hostlink-v2-authorized_keys"),
            gateways: vec![GatewayEndpoint {
                host: "gateway.example.test".into(),
                user: "hostlink-gateway".into(),
                port: 22,
                host_public_key: gateway_key.clone(),
            }],
            operator_ssh_public_keys: vec![operator_key.clone()],
            operator_token: OPERATOR.into(),
            gateway_lookup_token: EDGE.into(),
            port_from: 41000,
            port_to: 41010,
            reserved_ports: BTreeSet::new(),
        };
        assert!(HubService::new(config).is_err(), "{invalid_url}");
        assert!(
            !root.exists(),
            "invalid URL must fail before allocating persistent Hub state"
        );
    }
}

#[test]
fn new_hub_rejects_legacy_authorized_keys_projection_filename() {
    let dir = tempfile::tempdir().unwrap();
    let new_state_root = dir.path().join("hostlink-hub-v2");
    let old_authorized_keys = dir.path().join("gateway/authorized_keys");
    let config = HubConfig {
        listen: "127.0.0.1:27400".parse().unwrap(),
        public_url: "https://hub.example.test".into(),
        state_root: new_state_root.clone(),
        authorized_keys: old_authorized_keys.clone(),
        gateways: vec![GatewayEndpoint {
            host: "gateway.example.test".into(),
            user: "hostlink-gateway".into(),
            port: 22,
            host_public_key: key(),
        }],
        operator_ssh_public_keys: vec![key()],
        operator_token: OPERATOR.into(),
        gateway_lookup_token: EDGE.into(),
        port_from: 41000,
        port_to: 41010,
        reserved_ports: BTreeSet::new(),
    };
    assert!(HubService::new(config).is_err());
    assert!(!new_state_root.exists());
    assert!(!old_authorized_keys.exists());
}
