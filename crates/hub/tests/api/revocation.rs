use super::*;
use axum::http::StatusCode;
use hostlink_hub::router;
use serde_json::json;

#[test]
fn aborted_host_mutations_preserve_state_but_lost_revoke_ack_is_not_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let token = runtime.block_on(invite(app.clone(), "node", None));
    let reverse = key();
    let (status, _) = runtime.block_on(call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(token, "node", "node", reverse.clone(), key())).unwrap(),
    ));
    assert_eq!(status, StatusCode::CREATED);
    let before = persisted(dir.path());
    let projection_path = dir.path().join("gateway/hostlink-v2-authorized_keys");
    let projection = std::fs::read(&projection_path).unwrap();
    for (method, uri, body) in [
        (
            "PATCH",
            "/v2/hosts/node/display-name",
            json!({"display_name":"Cancelled"}),
        ),
        ("DELETE", "/v2/hosts/node", json!({})),
    ] {
        abort_locked_request(dir.path(), app.clone(), method, uri, Some(OPERATOR), body);
        assert_eq!(persisted(dir.path()), before);
        assert_eq!(std::fs::read(&projection_path).unwrap(), projection);
    }
    runtime.block_on(lose_response(
        app.clone(),
        "DELETE",
        "/v2/hosts/node",
        Some(OPERATOR),
        json!({}),
    ));
    let committed = persisted(dir.path());
    assert!(committed["hosts"].as_object().unwrap().is_empty());
    assert_eq!(
        committed["audit"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["action"] == "revoke")
            .count(),
        1
    );
    assert!(
        !std::fs::read_to_string(&projection_path)
            .unwrap()
            .contains("hostlink-agent:node")
    );
    let (status, _) = runtime.block_on(call(
        app.clone(),
        "GET",
        "/v2/hosts/node",
        Some(OPERATOR),
        json!({}),
    ));
    assert_eq!(status, StatusCode::NOT_FOUND);
    let parts: Vec<_> = reverse.split_whitespace().collect();
    let (status, lookup) = runtime.block_on(call(
        app,
        "POST",
        "/internal/v2/ssh/authorized-key",
        Some(EDGE),
        json!({"key_type":parts[0],"key_blob":parts[1]}),
    ));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lookup["authorized"], false);
    assert_eq!(persisted(dir.path()), committed);
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
