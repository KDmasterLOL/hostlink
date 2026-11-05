use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use private_fs::PrivateDir;
use std::fs;
use tower::ServiceExt;

#[cfg(windows)]
mod windows;

#[test]
fn command_job_timeout_is_optional_and_legacy_payloads_remain_compatible() {
    let legacy: CommandJob =
        serde_json::from_str(r#"{"program":"example","args":[],"cwd":null}"#).unwrap();
    assert_eq!(legacy.timeout_seconds, None);
    assert_eq!(
        command_timeout_seconds(legacy.timeout_seconds).unwrap(),
        900
    );
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::json!({"program":"example","args":[],"cwd":null})
    );

    let configured = CommandJob {
        program: "example".into(),
        args: Vec::new(),
        cwd: None,
        timeout_seconds: Some(1),
    };
    assert_eq!(
        serde_json::to_value(configured).unwrap()["timeout_seconds"],
        1
    );
}

#[test]
fn command_job_timeout_bounds_are_positive_and_capped_at_four_hours() {
    assert_eq!(command_timeout_seconds(Some(1)).unwrap(), 1);
    assert_eq!(command_timeout_seconds(Some(14_400)).unwrap(), 14_400);
    assert_eq!(
        command_timeout_seconds(Some(0)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        command_timeout_seconds(Some(14_401)).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn worker_rejects_invalid_timeout_before_process_group_creation() {
    let result = super::worker::execute(
        CommandJob {
            program: "example".into(),
            args: Vec::new(),
            cwd: None,
            timeout_seconds: Some(0),
        },
        apalis_core::task::data::Data(super::worker::ExecutionContext {
            stop: processkit::CancellationToken::new(),
            uncertain: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn worker_enforces_short_command_timeout_with_processkit_containment() {
    let group = processkit::ProcessGroup::new().unwrap();
    if group.mechanism() != processkit::Mechanism::CgroupV2 {
        eprintln!("NOT RUN: cgroup-v2 containment unavailable for real command timeout");
        return;
    }
    drop(group);

    let result = super::worker::execute(
        CommandJob {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "sleep 5".into()],
            cwd: None,
            timeout_seconds: Some(1),
        },
        apalis_core::task::data::Data(super::worker::ExecutionContext {
            stop: processkit::CancellationToken::new(),
            uncertain: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
    )
    .await;
    assert!(result.is_err(), "a command exceeding its timeout must fail");
}

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
async fn board_advertises_bounded_command_timeout_without_submitting_a_job() {
    let (_parent, root) = private_job_root();
    let store = JobStore::initialize_fresh(&root).await.unwrap();
    let app = board::router(&store, "127.0.0.1:4040".parse().unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/new")
                .header("host", "127.0.0.1:4040")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-hostlink-command-timeout-max")
            .unwrap(),
        "14400"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM Jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "capability read must never create a job");
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
async fn board_marks_zero_exit_done_and_nonzero_exit_failed() {
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
    let jobs = [
        ("exit-zero", "exit 0", "Done", r#"{"Ok":0}"#),
        (
            "exit-seven",
            "exit 7",
            "Failed",
            r#"{"Err":"command exited with code 7"}"#,
        ),
    ];
    let mut ids = Vec::with_capacity(jobs.len());
    for (name, command, expected_status, expected_result) in jobs {
        let id = ulid::Ulid::generate().to_string();
        let mut accepted = false;
        for _ in 0..60 {
            match client
                .put(&url)
                .header("x-task-id", &id)
                // A terminal Failed state is deterministic only when the
                // upstream retry budget is explicitly one attempt.
                .header("x-task-max-attempts", "1")
                .json(&CommandJob {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), command.into()],
                    cwd: None,
                    timeout_seconds: None,
                })
                .send()
                .await
            {
                Ok(reply) => {
                    assert!(reply.status().is_success(), "native Apalis push: {reply:?}");
                    accepted = true;
                    break;
                }
                Err(error) if error.is_connect() => {}
                Err(error) => panic!("Board task submission outcome is uncertain: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(accepted, "board HTTP listener must accept {name}");
        ids.push((id, name, command, expected_status, expected_result));
    }

    let store = JobStore::open(&root).await.unwrap();
    for (id, name, command, expected_status, expected_result) in ids {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let (status, result, attempts, max_attempts): (String, Option<String>, i64, i64) =
                    sqlx::query_as(
                        "SELECT status,last_result,attempts,max_attempts FROM Jobs WHERE id=?",
                    )
                    .bind(&id)
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
                if status == expected_status {
                    assert_eq!(result.as_deref(), Some(expected_result));
                    assert_eq!((attempts, max_attempts), (1, 1));
                    break;
                }
                assert!(
                    matches!(status.as_str(), "Pending" | "Queued" | "Running"),
                    "unexpected state for {name} ({command}): {status}, {result:?}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("the real native command did not reach its expected state: {name}")
        });
    }
    store.close().await;
    shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
