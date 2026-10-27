use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hostlink_hub::{
    EnrollRequest, GatewayEndpoint, HubConfig, HubService, InviteRequest, MachineId,
};
use secrecy::SecretString;
use serde_json::Value;
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};
use tower::ServiceExt;

pub(crate) const OPERATOR: &str = "operator-token-for-test-0123456789-abcdef";
pub(crate) const EDGE: &str = "gateway-token-for-test-0123456789-abcdef";

pub(crate) fn key() -> String {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source");
    let private: ssh_key::PrivateKey = ssh_key::private::Ed25519Keypair::from_seed(&seed).into();
    private
        .public_key()
        .to_openssh()
        .expect("encode public key")
}
pub(crate) fn service(root: &std::path::Path, gateway_key: String) -> HubService {
    service_with_keys(
        root,
        gateway_key,
        root.join("gateway/hostlink-v2-authorized_keys"),
    )
}
pub(crate) fn service_with_keys(
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
pub(crate) async fn call(
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
pub(crate) async fn call_raw(
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
pub(crate) async fn invite(app: axum::Router, name: &str, rotate: Option<&str>) -> String {
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
pub(crate) fn enrollment(
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

/// Drop a polled HTTP request behind a real writer lock, then drain every
/// blocking continuation before the caller inspects disk. No scheduling sleeps.
pub(crate) fn abort_locked_request(
    root: &std::path::Path,
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) {
    use std::{future::Future, task::Poll, time::Duration};
    let writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("hostlink-hub-v2/registry-v2.lock"))
        .unwrap();
    writer.lock().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let health = runtime.block_on(async {
        let mut request = Box::pin(call(app.clone(), method, uri, token, body));
        // Poll through dispatch into spawn_blocking. Whether the worker is
        // queued or already waiting in lock(), it cannot publish yet.
        std::future::poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let health = tokio::time::timeout(
            Duration::from_secs(1),
            call(app, "GET", "/healthz", None, serde_json::json!({})),
        )
        .await;
        drop(request); // Server-side request cancellation, before lock release.
        writer.unlock().unwrap();
        health
    });
    // A detached spawn_blocking worker cannot escape the persistence assertion.
    drop(runtime);
    assert_eq!(health.unwrap().0, StatusCode::OK);
}

/// The server prepared a response, but the caller never received its status or
/// body. In particular, this must not recover a plaintext invite from storage.
pub(crate) async fn lose_response(
    app: axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    drop(
        app.oneshot(
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap(),
    );
}

pub(crate) fn persisted(root: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(root.join("hostlink-hub-v2/registry-v2.json")).unwrap())
        .unwrap()
}
