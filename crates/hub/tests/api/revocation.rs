use super::*;
use axum::http::StatusCode;
use hostlink_hub::router;
use serde_json::json;

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
