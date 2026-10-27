use super::*;
use axum::http::StatusCode;
use hostlink_hub::router;
use serde_json::{Value, json};

#[test]
fn aborted_enrollment_keeps_invite_unused_and_can_be_manually_reconciled() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let token = runtime.block_on(invite(app.clone(), "cancelled", None));
    let before = persisted(dir.path());
    let body = serde_json::to_value(enrollment(
        token,
        "cancelled-node",
        "cancelled",
        key(),
        key(),
    ))
    .unwrap();
    abort_locked_request(
        dir.path(),
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        body.clone(),
    );
    assert_eq!(persisted(dir.path()), before);
    assert!(
        !dir.path()
            .join("gateway/hostlink-v2-authorized_keys")
            .exists()
    );
    // Explicit new request only after authoritative no-commit evidence.
    let (status, _) = runtime.block_on(call(app, "POST", "/v2/enroll", None, body));
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(persisted(dir.path())["hosts"].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn lost_enrollment_response_does_not_roll_back_or_allow_token_replay() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let token = invite(app.clone(), "unknown", None).await;
    let body = serde_json::to_value(enrollment(
        token.clone(),
        "unknown-node",
        "unknown",
        key(),
        key(),
    ))
    .unwrap();
    lose_response(app.clone(), "POST", "/v2/enroll", None, body.clone()).await;
    let committed = persisted(dir.path());
    assert_eq!(
        committed["invites"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["used"],
        true
    );
    assert!(!committed.to_string().contains(&token));
    let (status, host) = call(
        app.clone(),
        "GET",
        "/v2/hosts/unknown-node",
        Some(OPERATOR),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(host["machine_id"], "unknown-node");
    assert!(
        std::fs::read_to_string(dir.path().join("gateway/hostlink-v2-authorized_keys"))
            .unwrap()
            .contains("hostlink-agent:unknown-node")
    );
    let (status, _) = call(app, "POST", "/v2/enroll", None, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(persisted(dir.path()), committed);
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
