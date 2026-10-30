use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use private_fs::PrivateDir;
use std::fs;
use tower::ServiceExt;

fn private_job_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    // The library creates the private root with 0700 or owner-only Windows ACL.
    fs::remove_dir(parent.path()).unwrap();
    let private = PrivateDir::ensure(parent.path()).unwrap();
    private.create_dir("jobs").unwrap();
    let root = parent.path().join("jobs");
    (parent, root)
}

#[tokio::test]
async fn board_creates_and_lists_typed_tasks_and_serves_assets() {
    let (_parent, root) = private_job_root();
    let store = JobStore::initialize_fresh(&root).await.unwrap();
    let address = "127.0.0.1:4040".parse().unwrap();
    let app = board::router(&store, address);
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/queues/commands/tasks")
        .header("host", "127.0.0.1:4040")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"program":"example","args":["one"],"cwd":null}"#,
        ))
        .unwrap();
    assert!(
        app.clone()
            .oneshot(request)
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let request = Request::builder()
        .uri("/api/v1/queues/commands/tasks")
        .header("host", "127.0.0.1:4040")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("example"));
    let request = Request::builder()
        .uri("/")
        .header("host", "127.0.0.1:4040")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let request = Request::builder()
        .uri("/apalis-board-web-5f43ae260a03616d_bg.wasm")
        .header("host", "127.0.0.1:4040")
        .body(Body::empty())
        .unwrap();
    let wasm = app.clone().oneshot(request).await.unwrap();
    assert_eq!(wasm.status(), StatusCode::OK);
    assert_eq!(
        wasm.headers().get("content-type").unwrap(),
        "application/wasm"
    );
    assert!(
        to_bytes(wasm.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap()
            .starts_with(b"\0asm")
    );
    let request = Request::builder()
        .uri("/new")
        .header("host", "evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let task_count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(task_count, 1);
    store.close().await;
}

#[tokio::test]
async fn board_host_header_uses_exact_tower_validation() {
    let (_parent, root) = private_job_root();
    let store = JobStore::initialize_fresh(&root).await.unwrap();
    let app = board::router(&store, "127.0.0.1:4040".parse().unwrap());

    for (host, origin, expected) in [
        (None, None, StatusCode::FORBIDDEN),
        (Some("evil.example:4040"), None, StatusCode::FORBIDDEN),
        (Some("localhost:4040"), None, StatusCode::FORBIDDEN),
        (Some("127.0.0.1:4040"), None, StatusCode::OK),
        (
            Some("127.0.0.1:4040"),
            Some("http://evil.example"),
            StatusCode::FORBIDDEN,
        ),
        (
            Some("127.0.0.1:4040"),
            Some("http://127.0.0.1:4040"),
            StatusCode::OK,
        ),
    ] {
        let mut request = Request::builder().uri("/new");
        if let Some(host) = host {
            request = request.header("host", host);
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "host={host:?}, origin={origin:?}"
        );
    }
    store.close().await;
}

#[tokio::test]
async fn board_preserves_upstream_task_headers_without_hostlink_overrides() {
    let (_parent, root) = private_job_root();
    let store = JobStore::initialize_fresh(&root).await.unwrap();
    let app = board::router(&store, "127.0.0.1:4040".parse().unwrap());

    for max_attempts in [None, Some("99")] {
        let id = ulid::Ulid::generate().to_string();
        let mut request = Request::builder()
            .method("PUT")
            .uri("/api/v1/queues/commands/tasks")
            .header("host", "127.0.0.1:4040")
            .header("content-type", "application/json")
            .header("x-task-id", &id)
            .header("x-task-status", "Pending")
            .header("x-task-attempt", "2");
        if let Some(max_attempts) = max_attempts {
            request = request.header("x-task-max-attempts", max_attempts);
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::from(r#"{"program":"example","args":[],"cwd":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "upstream Apalis must accept native task metadata: {}",
            response.status()
        );
        let stored: i64 = sqlx::query_scalar("SELECT max_attempts FROM Jobs WHERE id=?")
            .bind(&id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, max_attempts.map_or(25, |v| v.parse().unwrap()));
    }
    store.close().await;
}

#[tokio::test]
async fn opening_existing_store_never_creates_a_missing_database() {
    let (_parent, root) = private_job_root();
    assert!(JobStore::open(&root).await.is_err());
    assert!(!root.join("jobs.db").exists());
}

#[tokio::test]
async fn native_apalis_schema_is_reused_without_hostlink_migrations() {
    let (_parent, root) = private_job_root();

    let store = JobStore::initialize_fresh(&root).await.unwrap();
    let migrations: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(migrations > 0);
    let extra: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='DurableMeta'",
    )
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        extra, 0,
        "only upstream Apalis migrations should create tables"
    );
    store.close().await;

    let reopened = JobStore::open(&root).await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&reopened.pool)
        .await
        .unwrap();
    assert_eq!(after, migrations);
    reopened.close().await;
}

#[tokio::test]
async fn preexisting_v5_database_keeps_legacy_marker_and_native_tasks() {
    let (_parent, root) = private_job_root();

    let old = JobStore::initialize_fresh(&root).await.unwrap();
    sqlx::query("CREATE TABLE DurableMeta(id INTEGER PRIMARY KEY, version INTEGER NOT NULL)")
        .execute(&old.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO DurableMeta(id,version) VALUES(1,5)")
        .execute(&old.pool)
        .await
        .unwrap();
    let app = board::router(&old, "127.0.0.1:4040".parse().unwrap());
    let request = Request::builder()
        .method("PUT")
        .uri("/api/v1/queues/commands/tasks")
        .header("host", "127.0.0.1:4040")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"program":"example","args":[],"cwd":null}"#))
        .unwrap();
    assert!(app.oneshot(request).await.unwrap().status().is_success());
    old.close().await;

    let reopened = JobStore::open(&root).await.unwrap();
    let version: i64 = sqlx::query_scalar("SELECT version FROM DurableMeta WHERE id=1")
        .fetch_one(&reopened.pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
        .fetch_one(&reopened.pool)
        .await
        .unwrap();
    assert_eq!((version, count), (5, 1));
    reopened.close().await;
}

#[tokio::test]
async fn worker_stops_on_agent_shutdown() {
    let (_parent, root) = private_job_root();
    JobStore::initialize_fresh(&root)
        .await
        .unwrap()
        .close()
        .await;
    let stop = processkit::CancellationToken::new();
    let token = stop.clone();
    let task = tokio::spawn(async move { serve_until(&root, None, token).await });
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    stop.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn board_serves_http_until_shutdown() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let (_parent, root) = private_job_root();
    JobStore::initialize_fresh(&root)
        .await
        .unwrap()
        .close()
        .await;
    let stop = processkit::CancellationToken::new();
    let token = stop.clone();
    let task = tokio::spawn(async move { serve_until(&root, Some(address), token).await });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/new");
    let mut response = None;
    for _ in 0..30 {
        if let Ok(value) = client.get(&url).send().await {
            response = Some(value);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(response.unwrap().status(), reqwest::StatusCode::OK);
    stop.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn board_submitted_command_executes_and_apalis_persists_exit_code() {
    // Real process execution requires a delegated cgroup v2, not the weaker
    // POSIX process-group fallback.
    let group = processkit::ProcessGroup::new().unwrap();
    if group.mechanism() != processkit::Mechanism::CgroupV2 {
        eprintln!("NOT RUN: cgroup-v2 containment unavailable for real command execution");
        return;
    }
    drop(group);
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reservation.local_addr().unwrap();
    drop(reservation);

    let (_parent, root) = private_job_root();
    JobStore::initialize_fresh(&root)
        .await
        .unwrap()
        .close()
        .await;

    let shutdown = processkit::CancellationToken::new();
    let stop = shutdown.clone();
    let jobs = root.clone();
    let server = tokio::spawn(async move { serve_until(&jobs, Some(addr), stop).await });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/queues/commands/tasks");
    let mut accepted = false;
    for _ in 0..60 {
        if let Ok(reply) = client
            .put(&url)
            .json(&CommandJob {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "exit 7".into()],
                cwd: None,
            })
            .send()
            .await
        {
            assert!(reply.status().is_success(), "native Apalis push: {reply:?}");
            accepted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(accepted, "board HTTP listener must accept a real command");

    let store = JobStore::open(&root).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let (status, result): (String, Option<String>) =
                sqlx::query_as("SELECT status,last_result FROM Jobs LIMIT 1")
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
            if status == "Done" {
                assert_eq!(result.unwrap(), r#"{"Ok":7}"#);
                break;
            }
            assert!(matches!(status.as_str(), "Pending" | "Queued" | "Running"));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the real native command completes and Apalis persists its result");
    store.close().await;
    shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
