use super::*;
use axum::http::StatusCode;
use hostlink_hub::router;
use serde_json::{Value, json};
use std::{fs::OpenOptions, sync::mpsc, thread, time::Duration};

#[test]
fn aborted_invite_before_writer_admission_never_commits() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    abort_locked_request(
        dir.path(),
        app.clone(),
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        json!({"ttl_seconds":30,"name":"cancelled"}),
    );
    assert!(!dir.path().join("hostlink-hub-v2/registry-v2.json").exists());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let token = runtime.block_on(invite(app, "cancelled", None));
    let state = persisted(dir.path());
    assert_eq!(state["invites"].as_object().unwrap().len(), 1);
    assert_eq!(state["audit"].as_array().unwrap().len(), 1);
    assert!(!state.to_string().contains(&token));
}

#[tokio::test]
async fn lost_invite_response_keeps_only_an_expiring_digest() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    lose_response(
        app.clone(),
        "POST",
        "/v2/invites",
        Some(OPERATOR),
        json!({"ttl_seconds":30,"name":"unknown"}),
    )
    .await;
    let mut state = persisted(dir.path());
    let created_at = state["audit"][0]["at"].as_i64().unwrap();
    let invites = state["invites"].as_object().unwrap();
    assert_eq!(invites.len(), 1); // A lost ACK is not rollback.
    let (digest, record) = invites.iter().next().unwrap();
    let digest = digest.clone();
    assert_eq!(digest.len(), 64);
    assert_eq!(record["digest"], digest);
    assert!(record.get("token").is_none());
    assert_eq!(record["used"], false);
    assert!((0..=30).contains(&(record["expires_at"].as_i64().unwrap() - created_at)));
    // Operator waits for expiry; no blind retry and no secret readback.
    state["invites"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap()["expires_at"] = json!(0);
    std::fs::write(
        dir.path().join("hostlink-hub-v2/registry-v2.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    invite(app, "unknown", None).await;
    let reconciled = persisted(dir.path());
    assert_eq!(reconciled["invites"].as_object().unwrap().len(), 1);
    assert!(
        !reconciled["invites"]
            .as_object()
            .unwrap()
            .contains_key(&digest)
    );
    assert_eq!(reconciled["audit"].as_array().unwrap().len(), 2);
}

#[test]
fn state_lock_wait_does_not_block_health_on_the_tokio_executor() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(service(dir.path(), key()));
    let lock_path = dir.path().join("hostlink-hub-v2/registry-v2.lock");
    let writer_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    writer_lock.lock().unwrap();

    let (progress_tx, progress_rx) = mpsc::sync_channel(1);
    let request_app = app.clone();
    let health_app = app;
    let request_thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let list_request = tokio::spawn(call(
                request_app,
                "GET",
                "/v2/hosts",
                Some(OPERATOR),
                json!({}),
            ));
            tokio::time::sleep(Duration::from_millis(50)).await;
            let health_progressed = tokio::time::timeout(
                Duration::from_millis(500),
                call(health_app, "GET", "/healthz", None, json!({})),
            )
            .await
            .is_ok();
            let _ = progress_tx.send(health_progressed);
            list_request.await.unwrap()
        })
    });

    // Observe progress before releasing the lock. Always release it before
    // asserting so a regression cannot strand the request thread.
    let health_progressed = progress_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(false);
    writer_lock.unlock().unwrap();
    let (status, _) = request_thread.join().unwrap();

    assert!(
        health_progressed,
        "health waited behind the state file lock"
    );
    assert_eq!(status, StatusCode::OK);
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
