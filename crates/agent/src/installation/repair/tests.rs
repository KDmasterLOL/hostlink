use super::*;
use crate::executable::test_image;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hostlink_hub::{GatewayEndpoint, HubConfig, HubService};
use russh::keys::ssh_key::LineEnding;
use serde_json::{Value, json};
use tower::ServiceExt;

const OPERATOR: &str = "disposable-repair-fixture-operator";

async fn call(app: axum::Router, uri: &str, body: Value, operator: bool) -> (StatusCode, Value) {
    let mut builder = Request::post(uri).header("content-type", "application/json");
    if operator {
        builder = builder.header("authorization", format!("Bearer {OPERATOR}"));
    }
    let response = app
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn hub(root: &Path, gateway: GatewayEndpoint) -> axum::Router {
    hostlink_hub::router(
        HubService::new(HubConfig {
            listen: "127.0.0.1:27400".parse().unwrap(),
            public_url: "https://hub.invalid".into(),
            state_root: root.join("hostlink-hub-v2"),
            authorized_keys: root.join("projection/hostlink-v2-authorized_keys"),
            gateways: vec![gateway],
            operator_ssh_public_keys: vec![
                enrollment::public_key(
                    &PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
                )
                .unwrap(),
            ],
            operator_token: OPERATOR.to_owned().into(),
            gateway_lookup_token: "disposable-repair-fixture-gateway".to_owned().into(),
            port_from: 41000,
            port_to: 41100,
            reserved_ports: Default::default(),
        })
        .unwrap(),
    )
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    app: axum::Router,
    snapshot: Snapshot,
    gateway: tokio::task::JoinHandle<io::Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.gateway.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        // Create protected Windows ACLs as well as Unix private modes.
        fs::remove_dir(temp.path()).unwrap();
        let dir = PrivateDir::ensure(temp.path()).unwrap();
        dir.create_dir("projection").unwrap();
        let pin = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let app = hub(
            temp.path(),
            GatewayEndpoint {
                host: "stale.invalid".into(),
                port: 22,
                user: "gateway".into(),
                host_public_key: enrollment::public_key(&pin).unwrap(),
            },
        );
        let (status, invite) =
            call(app.clone(), "/v2/invites", json!({"name":"offline"}), true).await;
        assert_eq!(status, StatusCode::CREATED);
        let token = temp.path().join("token");
        enrollment::write_private_new(&token, invite["token"].as_str().unwrap().as_bytes())
            .unwrap();
        let root = temp.path().join("Agent");
        let options = enrollment::EnrollmentOptions {
            hub_url: "https://hub.invalid".into(),
            token_file: token,
            install_root: root.clone(),
            name: "offline".into(),
            user: "agent".into(),
            gateway_index: None,
            retain_pending: true,
        };
        enrollment::prepare_enrollment_using(&options, |_, request| async {
            let (status, response) = call(
                app.clone(),
                "/v2/enroll",
                serde_json::to_value(request).unwrap(),
                false,
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            serde_json::from_value(response).map_err(io::Error::other)
        })
        .await
        .unwrap();
        let (_image, mut source) = test_image();
        super::super::publish_executable(&root, &mut source).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("jobs/jobs.db"), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let identity: enrollment::EnrollmentIdentity =
            serde_json::from_slice(&fs::read(root.join("state/machine.json")).unwrap()).unwrap();
        let snapshot = Snapshot::read(&root, &identity.machine_id, "offline", "agent").unwrap();
        let ssh_dir = dir.create_dir("gateway").unwrap();
        let gateway_root = temp.path().join("gateway");
        let new_pin = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut key = ssh_dir.create("host_key").unwrap();
        key.write_all(new_pin.to_openssh(LineEnding::LF).unwrap().as_bytes())
            .unwrap();
        drop(key);
        let mut allowed = ssh_dir.create("authorized_keys").unwrap();
        allowed
            .write_all(snapshot.identity.ssh_public_key.as_bytes())
            .unwrap();
        drop(allowed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = AgentConfig {
            listen: addr,
            user: "gateway".into(),
            host_key: gateway_root.join("host_key"),
            authorized_keys: gateway_root.join("authorized_keys"),
            jobs_root: root.join("jobs"),
            board_listen: None,
            gateway: None,
            gateway_alternates: vec![],
        };
        let prepared = crate::ssh::prepare(&config).unwrap();
        let transfer = root.join("jobs");
        let gateway = tokio::spawn(crate::ssh::serve_prepared_until(
            listener,
            prepared,
            transfer,
            std::future::pending::<()>(),
        ));
        // Simulate a Hub-approved route+pin migration without touching the installed state.
        let app = hub(
            temp.path(),
            GatewayEndpoint {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: "gateway".into(),
                host_public_key: enrollment::public_key(&new_pin).unwrap(),
            },
        );
        Self {
            _temp: temp,
            root,
            app,
            snapshot,
            gateway,
        }
    }

    async fn repair_response(&self) -> EnrollResponse {
        let (status, invite) = call(
            self.app.clone(),
            "/v2/invites",
            json!({"name":"offline", "repair_machine_id":self.snapshot.identity.machine_id}),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let mut request = self
            .snapshot
            .request(invite["token"].as_str().unwrap().to_owned().into())
            .unwrap();
        request.repair_signature = Some(
            self.snapshot
                .reverse_key
                .sign(REPAIR_NAMESPACE, HashAlg::Sha256, &request.repair_message())
                .unwrap()
                .to_string(),
        );
        let (status, response) = call(
            self.app.clone(),
            "/v2/enroll",
            serde_json::to_value(request).unwrap(),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        serde_json::from_value(response).unwrap()
    }
}

#[tokio::test]
async fn authorized_stale_route_repair_preserves_identity_jobs_and_private_state() {
    use apalis_core::backend::TaskSink;
    let f = Fixture::new().await;
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        f.root.join("jobs/jobs.db").display()
    ))
    .await
    .unwrap();
    let mut jobs = apalis_sqlite::SqliteStorage::new(&pool)
        .with_config(apalis_sqlite::Config::default().queue("commands"));
    jobs.push(crate::jobs::CommandJob {
        program: "preserved-job".into(),
        args: vec![],
        cwd: None,
        timeout_seconds: None,
    })
    .await
    .unwrap();
    pool.close().await;
    let database = fs::read(f.root.join("jobs/jobs.db")).unwrap();
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    assert!(crate::installation::ensure_ready(&f.root).is_err());
    let response = f.repair_response().await;
    transaction
        .write_candidate(&f.snapshot, &response, None)
        .await
        .unwrap();
    assert!(transaction.changed(&f.snapshot).unwrap());
    transaction.publish().unwrap();
    transaction.finish().unwrap();
    let after =
        Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "offline", "agent").unwrap();
    for name in ["host_key", "gateway_identity", "authorized_keys"] {
        assert_eq!(after.files[name], f.snapshot.files[name]);
    }
    assert_eq!(after.identity.remote_port, f.snapshot.identity.remote_port);
    assert_eq!(
        after.identity.ssh_public_key,
        f.snapshot.identity.ssh_public_key
    );
    assert_eq!(
        after.identity.ssh_host_public_key,
        f.snapshot.identity.ssh_host_public_key
    );
    assert_eq!(fs::read(f.root.join("jobs/jobs.db")).unwrap(), database);
    assert_ne!(after.identity.gateway, f.snapshot.identity.gateway);
    let mut config = after.config.clone();
    config.resolve_relative_paths(&f.root.join("state"));
    crate::tunnel::probe(&config).await.unwrap();
    // Identical pins/config/image do not require a second publication or service stop.
    let (_temp, mut image) = test_image();
    let repeat = Transaction::prepare(&f.root, &after, &mut image).unwrap();
    repeat.mark_pending().unwrap();
    repeat
        .write_candidate(&after, &response, None)
        .await
        .unwrap();
    assert!(!repeat.changed(&after).unwrap());
    repeat.finish().unwrap();
}

#[tokio::test]
async fn damaged_foreign_mismatched_and_pending_roots_are_preserved() {
    let f = Fixture::new().await;
    assert!(
        Snapshot::read(
            &f.root,
            &MachineId::parse("other").unwrap(),
            "offline",
            "agent"
        )
        .is_err()
    );
    assert!(Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "other", "agent").is_err());
    assert!(Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "offline", "other").is_err());
    for marker in ["enrollment.pending", "repair.pending"] {
        enrollment::write_private_new(&f.root.join(marker), b"uncertain").unwrap();
        assert!(
            Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "offline", "agent").is_err()
        );
        fs::remove_file(f.root.join(marker)).unwrap();
    }
    let host = f.root.join("state/host_key");
    let original = fs::read(&host).unwrap();
    fs::write(&host, b"damaged").unwrap();
    assert!(Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "offline", "agent").is_err());
    assert_eq!(fs::read(&host).unwrap(), b"damaged");
    fs::write(host, original).unwrap();
    let foreign = f._temp.path().join("foreign");
    PrivateDir::ensure(&foreign).unwrap();
    enrollment::write_private_new(&foreign.join("owner"), b"foreign").unwrap();
    assert!(
        Snapshot::read(
            &foreign,
            &f.snapshot.identity.machine_id,
            "offline",
            "agent"
        )
        .is_err()
    );
    assert_eq!(fs::read(foreign.join("owner")).unwrap(), b"foreign");
}

#[tokio::test]
async fn partial_publication_rolls_back_and_missing_binary_can_be_restored() {
    let f = Fixture::new().await;
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    let response = f.repair_response().await;
    transaction
        .write_candidate(&f.snapshot, &response, None)
        .await
        .unwrap();
    let stage = fs::read_dir(&f.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".repair-")
        })
        .unwrap();
    // A real filesystem collision injects failure after state was published.
    let collision = PrivateDir::open(&stage)
        .unwrap()
        .create_dir("original-bin")
        .unwrap();
    collision.create("collision").unwrap();
    drop(collision);
    assert!(transaction.publish().is_err());
    fs::remove_file(stage.join("original-bin/collision")).unwrap();
    fs::remove_dir(stage.join("original-bin")).unwrap();
    transaction.rollback().unwrap();
    transaction.finish().unwrap();
    f.snapshot.assert_unchanged(&f.root).unwrap();
    assert!(!f.root.join("repair.pending").exists());
    fs::remove_file(f.root.join("bin").join(EXECUTABLE_NAME)).unwrap();
    let (_temp, mut image) = test_image();
    let repair = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    repair.mark_pending().unwrap();
    repair
        .write_candidate(&f.snapshot, &response, None)
        .await
        .unwrap();
    repair.publish().unwrap();
    repair.finish().unwrap();
    verify_executable(&f.root.join("bin").join(EXECUTABLE_NAME)).unwrap();
}

#[tokio::test]
async fn wrong_gateway_pin_and_changed_port_never_publish() {
    let f = Fixture::new().await;
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    let mut response = f.repair_response().await;
    response.host.remote_port += 1;
    assert!(
        transaction
            .write_candidate(&f.snapshot, &response, None)
            .await
            .is_err()
    );
    response.host.remote_port -= 1;
    response.gateways[0].host_public_key = f.snapshot.identity.gateway.host_public_key.clone();
    assert!(
        transaction
            .write_candidate(&f.snapshot, &response, None)
            .await
            .is_err()
    );
    f.snapshot.assert_unchanged(&f.root).unwrap();
    assert!(f.root.join("repair.pending").exists());
}

#[tokio::test]
async fn lost_keys_require_rotation_and_attempted_new_keys_survive_a_lost_ack() {
    let f = Fixture::new().await;
    fs::remove_file(f.root.join("state/gateway_identity")).unwrap();
    fs::write(f.root.join("state/host_key"), b"damaged-private-key").unwrap();
    assert!(Snapshot::read(&f.root, &f.snapshot.identity.machine_id, "offline", "agent").is_err());
    let replacement =
        Snapshot::read_replacement(&f.root, &f.snapshot.identity.machine_id, "offline", "agent")
            .unwrap();
    assert_ne!(
        replacement.identity.ssh_public_key,
        f.snapshot.identity.ssh_public_key
    );
    assert_ne!(
        replacement.identity.ssh_host_public_key,
        f.snapshot.identity.ssh_host_public_key
    );
    assert_eq!(
        replacement.identity.remote_port,
        f.snapshot.identity.remote_port
    );
    let database = fs::read(f.root.join("jobs/jobs.db")).unwrap();
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &replacement, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    let stage = fs::read_dir(&f.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".repair-")
        })
        .unwrap();
    let attempt = PrivateDir::open(stage.join("attempt")).unwrap();
    for (name, expected) in [
        ("gateway_identity", &replacement.identity.ssh_public_key),
        ("host_key", &replacement.identity.ssh_host_public_key),
    ] {
        let key = PrivateKey::from_openssh(state::read(&attempt, name).unwrap()).unwrap();
        assert_eq!(&enrollment::public_key(&key).unwrap(), expected);
    }
    let (status, invite) = call(
        f.app.clone(),
        "/v2/invites",
        json!({"name":"offline", "repair_machine_id":replacement.identity.machine_id}),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let request = replacement
        .request(invite["token"].as_str().unwrap().to_owned().into())
        .unwrap();
    let (status, _) = call(
        f.app.clone(),
        "/v2/enroll",
        serde_json::to_value(request).unwrap(),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, invite) = call(
        f.app.clone(),
        "/v2/invites",
        json!({"name":"offline", "rotate_machine_id":replacement.identity.machine_id}),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let request = replacement
        .request(invite["token"].as_str().unwrap().to_owned().into())
        .unwrap();
    let body = serde_json::to_value(request).unwrap();
    let (status, response) = call(f.app.clone(), "/v2/enroll", body.clone(), false).await;
    assert_eq!(status, StatusCode::CREATED);
    // Treat the successful reply as lost: no local publication, no token retry.
    drop(transaction);
    assert!(crate::installation::ensure_ready(&f.root).is_err());
    assert!(!f.root.join("state/gateway_identity").exists());
    let response: EnrollResponse = serde_json::from_value(response).unwrap();
    let candidate = replacement.candidate(&response, None).unwrap();
    assert_eq!(response.host.machine_id, f.snapshot.identity.machine_id);
    assert_eq!(response.host.remote_port, f.snapshot.identity.remote_port);
    assert_eq!(
        PrivateKey::from_openssh(&candidate["host_key"])
            .unwrap()
            .public_key(),
        PrivateKey::from_openssh(state::read(&attempt, "host_key").unwrap())
            .unwrap()
            .public_key()
    );
    let (status, _) = call(f.app.clone(), "/v2/enroll", body, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fs::read(f.root.join("jobs/jobs.db")).unwrap(), database);
}

#[tokio::test]
async fn incomplete_rollback_keeps_marker_backup_and_blocks_restart() {
    let f = Fixture::new().await;
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    let response = f.repair_response().await;
    transaction
        .write_candidate(&f.snapshot, &response, None)
        .await
        .unwrap();
    transaction.publish().unwrap();
    transaction.finish().unwrap();
    transaction.retain_pending().unwrap();
    let stage = fs::read_dir(&f.root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".repair-")
        })
        .unwrap();
    let collision = PrivateDir::open(&stage)
        .unwrap()
        .create_dir("failed-bin")
        .unwrap();
    collision.create("preserve").unwrap();
    assert!(transaction.rollback().is_err());
    assert!(stage.join("original-state").is_dir());
    assert!(stage.join("original-bin").is_dir());
    assert!(crate::installation::ensure_ready(&f.root).is_err());
}

#[tokio::test]
async fn approved_fallback_probe_succeeds_without_an_agent_remote_channel() {
    let f = Fixture::new().await;
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    let mut response = f.repair_response().await;
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut unreachable = response.gateways[0].clone();
    unreachable.port = closed.local_addr().unwrap().port();
    drop(closed);
    response.gateways.insert(0, unreachable);
    // Only the fixture gateway's real SSH server is running. No installed Agent
    // or reverse listener exists; the probe merely authenticates outbound SSH.
    transaction
        .write_candidate(&f.snapshot, &response, Some(0))
        .await
        .unwrap();
    f.snapshot.assert_unchanged(&f.root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn private_identity_symlink_is_never_followed_even_for_rotation() {
    let f = Fixture::new().await;
    let path = f.root.join("state/gateway_identity");
    fs::rename(&path, f.root.join("retained-key")).unwrap();
    std::os::unix::fs::symlink(f.root.join("retained-key"), &path).unwrap();
    assert!(
        Snapshot::read_replacement(&f.root, &f.snapshot.identity.machine_id, "offline", "agent")
            .is_err()
    );
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
}

#[tokio::test]
async fn mismatched_candidate_and_concurrently_changed_executable_are_preserved() {
    let f = Fixture::new().await;
    let (_temp, mut image) = test_image();
    image.sha256 = "00".repeat(32);
    assert!(Transaction::prepare(&f.root, &f.snapshot, &mut image).is_err());
    assert!(!f.root.join("repair.pending").exists());
    f.snapshot.assert_unchanged(&f.root).unwrap();
    let (_temp, mut image) = test_image();
    let transaction = Transaction::prepare(&f.root, &f.snapshot, &mut image).unwrap();
    transaction.mark_pending().unwrap();
    let response = f.repair_response().await;
    transaction
        .write_candidate(&f.snapshot, &response, None)
        .await
        .unwrap();
    let binary = f.root.join("bin").join(EXECUTABLE_NAME);
    fs::write(&binary, b"concurrently-changed").unwrap();
    assert!(transaction.publish().is_err());
    f.snapshot.assert_unchanged(&f.root).unwrap();
    assert_eq!(fs::read(binary).unwrap(), b"concurrently-changed");
    assert!(f.root.join("repair.pending").exists());
}
