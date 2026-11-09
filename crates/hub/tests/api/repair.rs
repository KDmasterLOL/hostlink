use super::*;
use axum::http::StatusCode;
use hostlink_hub::{REPAIR_NAMESPACE, router};
use serde_json::{Value, json};
use ssh_key::{HashAlg, PrivateKey, private::Ed25519Keypair};

fn private_key() -> PrivateKey {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    Ed25519Keypair::from_seed(&seed).into()
}

async fn repair_invite(app: axum::Router, id: &str, name: &str) -> String {
    let (status, response) = call(
        app,
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        json!({"name": name, "repair_machine_id": id}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    response["token"].as_str().unwrap().into()
}

#[tokio::test]
async fn repair_requires_both_exact_identity_and_token_bound_possession() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let reverse = private_key();
    let public = reverse.public_key().to_openssh().unwrap();
    let host = key();
    let token = invite(app.clone(), "offline", None).await;
    let (_, enrolled) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "offline-id",
            "offline",
            public.clone(),
            host.clone(),
        ))
        .unwrap(),
    )
    .await;
    let token = repair_invite(app.clone(), "offline-id", "offline").await;
    let mut request = enrollment(
        token.clone(),
        "offline-id",
        "offline",
        public.clone(),
        host.clone(),
    );
    let signature = reverse
        .sign(REPAIR_NAMESPACE, HashAlg::Sha256, &request.repair_message())
        .unwrap()
        .to_string();
    for mutation in [
        "missing-proof",
        "wrong-signer",
        "wrong-id",
        "wrong-name",
        "changed-key",
        "different-token",
        "changed-inventory",
    ] {
        let mut attempt = request.clone();
        attempt.repair_signature = Some(signature.clone());
        match mutation {
            "missing-proof" => attempt.repair_signature = None,
            "wrong-signer" => {
                attempt.repair_signature = Some(
                    private_key()
                        .sign(REPAIR_NAMESPACE, HashAlg::Sha256, &attempt.repair_message())
                        .unwrap()
                        .to_string(),
                )
            }
            "wrong-id" => attempt.machine_id = "other-id".parse().unwrap(),
            "wrong-name" => attempt.name = "wrong".into(),
            "changed-key" => attempt.ssh_host_public_key = key(),
            "different-token" => {
                attempt.token = repair_invite(app.clone(), "offline-id", "offline")
                    .await
                    .into()
            }
            "changed-inventory" => attempt.hostname = "tampered".into(),
            _ => unreachable!(),
        }
        let before = persisted(dir.path());
        let (status, _) = call(
            app.clone(),
            "POST",
            "/v2/enroll",
            None,
            serde_json::to_value(attempt).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{mutation}");
        assert_eq!(persisted(dir.path()), before, "{mutation}");
    }
    request.repair_signature = Some(signature);
    let body = serde_json::to_value(&request).unwrap();
    let (status, repaired) = call(app.clone(), "POST", "/v2/enroll", None, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    for field in [
        "machine_id",
        "name",
        "remote_port",
        "ssh_public_key",
        "ssh_host_public_key",
        "enrolled_at",
    ] {
        assert_eq!(repaired["host"][field], enrolled["host"][field], "{field}");
    }
    assert_eq!(persisted(dir.path())["hosts"].as_object().unwrap().len(), 1);
    let committed = persisted(dir.path());
    let (status, _) = call(app, "POST", "/v2/enroll", None, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(persisted(dir.path()), committed);
}

#[tokio::test]
async fn repair_issuance_rejects_wrong_name_missing_host_and_mixed_purpose() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let token = invite(app.clone(), "node", None).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(token, "node-id", "node", key(), key())).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    for (body, expected) in [
        (
            json!({"name":"wrong", "repair_machine_id":"node-id"}),
            StatusCode::CONFLICT,
        ),
        (json!({"repair_machine_id":"node-id"}), StatusCode::CONFLICT),
        (
            json!({"name":"node", "repair_machine_id":"missing"}),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({"name":"node", "repair_machine_id":"node-id", "rotate_machine_id":"node-id"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let before = persisted(dir.path());
        let (status, _) = call(app.clone(), "POST", "/v2/invites", Some(OPERATOR), body).await;
        assert_eq!(status, expected);
        assert_eq!(persisted(dir.path()), before);
    }
}

#[tokio::test]
async fn uncertain_repair_commit_is_one_use_and_expired_or_rotated_invites_fail() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let reverse = private_key();
    let public = reverse.public_key().to_openssh().unwrap();
    let host = key();
    let token = invite(app.clone(), "node", None).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(
            token,
            "node-id",
            "node",
            public.clone(),
            host.clone(),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let make_request = |token: String| {
        let mut request = enrollment(token, "node-id", "node", public.clone(), host.clone());
        request.repair_signature = Some(
            reverse
                .sign(REPAIR_NAMESPACE, HashAlg::Sha256, &request.repair_message())
                .unwrap()
                .to_string(),
        );
        serde_json::to_value(request).unwrap()
    };
    let token = repair_invite(app.clone(), "node-id", "node").await;
    let body = make_request(token);
    lose_response(app.clone(), "POST", "/v2/enroll", None, body.clone()).await;
    let before = persisted(dir.path());
    let (status, _) = call(app.clone(), "POST", "/v2/enroll", None, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(persisted(dir.path()), before);
    let token = repair_invite(app.clone(), "node-id", "node").await;
    let path = dir.path().join("hostlink-hub-v2/registry-v2.json");
    let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for invite in state["invites"].as_object_mut().unwrap().values_mut() {
        invite["expires_at"] = json!(1);
    }
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let (status, _) = call(app.clone(), "POST", "/v2/enroll", None, make_request(token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let token = repair_invite(app.clone(), "node-id", "node").await;
    let rotate = invite(app.clone(), "node", Some("node-id")).await;
    let (status, _) = call(
        app.clone(),
        "POST",
        "/v2/enroll",
        None,
        serde_json::to_value(enrollment(rotate, "node-id", "node", key(), key())).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let before = persisted(dir.path());
    let (status, _) = call(app, "POST", "/v2/enroll", None, make_request(token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(persisted(dir.path()), before);
}
