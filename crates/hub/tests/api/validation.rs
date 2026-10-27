use super::*;
use axum::http::StatusCode;
use hostlink_hub::{GatewayEndpoint, HubConfig, HubService, router};
use serde_json::json;
use std::{collections::BTreeSet, path::PathBuf};

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

#[tokio::test]
async fn gateway_lookup_uses_only_gateway_bearer_token_and_rejects_invalid_authorization() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let lookup_key = key();
    let (key_type, key_blob) = lookup_key.split_once(' ').unwrap();
    let body = json!({"key_type": key_type, "key_blob": key_blob});

    for authorization in [
        None,
        Some(format!("Basic {EDGE}")),
        Some(format!("Bearer {OPERATOR}")),
        Some("Bearer wrong-token".into()),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/internal/v2/ssh/authorized-key")
            .header("content-type", "application/json");
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let (status, response) = call(
        app,
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, json!({"authorized": false}));

    let (status, _) = call(
        router(service(dir.path(), key())),
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type": "ssh-ed25519", "key_blob": "not-base64"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
