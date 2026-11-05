#![cfg(target_os = "linux")]

use hostlink_agent::{AgentConfig, jobs::JobStore};
use rand::rng;
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

fn private_file(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).expect("write isolated fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("make isolated fixture file owner-only");
}

fn loopback_addresses() -> (SocketAddr, SocketAddr) {
    let ssh = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral SSH loopback port");
    let board = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral Board loopback port");
    let addresses = (
        ssh.local_addr().expect("read reserved SSH address"),
        board.local_addr().expect("read reserved Board address"),
    );
    drop((ssh, board));
    addresses
}

async fn stop_agent(agent: &mut Child) {
    if let Some(status) = agent.try_wait().expect("check source-built Agent") {
        panic!("source-built Agent exited before graceful shutdown: {status}");
    }
    let pid = agent.id().expect("running source-built Agent PID");
    // systemd --user stops the Agent with SIGTERM; exercise the same normal path.
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGTERM) }, 0);
    let status = tokio::time::timeout(Duration::from_secs(10), agent.wait())
        .await
        .expect("Agent did not exit after SIGTERM")
        .expect("wait for source-built Agent shutdown");
    assert!(status.success(), "Agent shutdown returned {status}");
}

#[tokio::test]
#[ignore = "requires owner-controlled Linux with delegated cgroup-v2 and loopback sockets"]
async fn source_built_agent_cli_reports_detached_command_exit_statuses() {
    // Explicit native acceptance fails rather than silently skipping.
    let group = processkit::ProcessGroup::new()
        .expect("native Agent acceptance requires process containment");
    assert_eq!(
        group.mechanism(),
        processkit::Mechanism::CgroupV2,
        "native Agent acceptance requires delegated cgroup-v2"
    );
    drop(group);

    let temp = tempfile::tempdir().expect("create isolated Agent fixture");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make fixture root private");
    let jobs_root = temp.path().join("jobs");
    std::fs::create_dir(&jobs_root).expect("create isolated Apalis root");
    std::fs::set_permissions(&jobs_root, std::fs::Permissions::from_mode(0o700))
        .expect("make Apalis root private");
    JobStore::initialize_fresh(&jobs_root)
        .await
        .expect("initialize fresh isolated Apalis SQLite database")
        .close()
        .await;

    let host_key =
        PrivateKey::random(&mut rng(), Algorithm::Ed25519).expect("generate SSH host key");
    let controller_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)
        .expect("generate authorized controller key");
    let host_key_path = temp.path().join("host_key");
    let authorized_keys_path = temp.path().join("authorized_keys");
    private_file(
        &host_key_path,
        host_key
            .to_openssh(LineEnding::LF)
            .expect("encode host key"),
    );
    private_file(
        &authorized_keys_path,
        format!(
            "{} isolated-controller\n",
            controller_key
                .public_key()
                .to_openssh()
                .expect("encode authorized key")
        ),
    );

    let (ssh_listen, board_listen) = loopback_addresses();
    let config = AgentConfig {
        listen: ssh_listen,
        user: "agent".into(),
        host_key: host_key_path,
        authorized_keys: authorized_keys_path,
        jobs_root: jobs_root.clone(),
        board_listen: Some(board_listen),
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let config_path = temp.path().join("agent.json");
    private_file(
        &config_path,
        serde_json::to_vec(&config).expect("serialize isolated Agent config"),
    );

    let mut agent = Command::new(env!("CARGO_BIN_EXE_hostlink-agent"))
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start current Cargo-built hostlink-agent executable");
    let submit_client = reqwest::Client::new();
    let board_url = format!("http://{board_listen}");
    let readiness_url = format!("{board_url}/new");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = agent.try_wait().expect("poll source-built Agent") {
                panic!("source-built Agent exited before Board readiness: {status}");
            }
            if let Ok(response) = submit_client.get(&readiness_url).send().await
                && response.status().is_success()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("source-built Agent Board did not become ready");

    let jobs = [
        ("exit-0", vec!["-c", "exit 0"], "Done", "{\"Ok\":0}"),
        (
            "exit-7",
            vec!["-c", "exit 7"],
            "Failed",
            "{\"Err\":\"command exited with code 7\"}",
        ),
    ];
    let mut task_ids = Vec::with_capacity(jobs.len());
    for (name, args, expected_status, expected_result) in jobs {
        let task_id = ulid::Ulid::generate().to_string();
        let submitted = submit_client
            .put(format!("{board_url}/api/v1/queues/commands/tasks"))
            .header("x-task-id", &task_id)
            .header("x-task-max-attempts", "1")
            .json(&serde_json::json!({
                "program": "/bin/sh",
                "args": args,
                "cwd": null,
                "timeout_seconds": null
            }))
            .send()
            .await
            .unwrap_or_else(|error| {
                panic!("{name} submit outcome is uncertain; never retry PUT: {error}")
            });
        assert!(
            submitted.status().is_success(),
            "Board rejected {name}: {}",
            submitted.status()
        );
        task_ids.push((task_id, name, expected_status, expected_result));
    }
    drop(submit_client);

    // This separate client models a disconnected submitter: only Board polling remains.
    let status_client = reqwest::Client::new();
    for (task_id, name, expected_status, expected_result) in task_ids {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = agent.try_wait().expect("check Agent while jobs execute") {
                    panic!("source-built Agent exited while {name} was running: {status}");
                }
                let response = status_client
                    .get(format!(
                        "{board_url}/api/v1/queues/commands/tasks/{task_id}"
                    ))
                    .send()
                    .await
                    .expect("poll official upstream Board task status");
                assert!(
                    response.status().is_success(),
                    "Board status lookup: {}",
                    response.status()
                );
                let task: Value = response.json().await.expect("decode Board task status");
                let status = task["ctx"]["status"]
                    .as_str()
                    .unwrap_or_else(|| panic!("Board task response has no string status: {task}"));
                if status == expected_status {
                    break;
                }
                assert!(
                    matches!(status, "Pending" | "Queued" | "Running"),
                    "unexpected {name} Board task state: {task}"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Board status for {name} did not reach {expected_status}"));

        let database = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(jobs_root.join("jobs.db"))
                    .create_if_missing(false)
                    .read_only(true),
            )
            .await
            .expect("open isolated Agent-owned Apalis database read-only");
        let (status, result, attempts, max_attempts): (String, Option<String>, i64, i64) =
            sqlx::query_as("SELECT status,last_result,attempts,max_attempts FROM Jobs WHERE id=?")
                .bind(&task_id)
                .fetch_one(&database)
                .await
                .expect("read accepted task fixture record");
        assert_eq!(status, expected_status, "SQLite task state for {name}");
        assert_eq!(
            result.as_deref(),
            Some(expected_result),
            "SQLite result for {name}"
        );
        assert_eq!((attempts, max_attempts), (1, 1), "one attempt for {name}");
        database.close().await;
    }

    assert!(
        agent
            .try_wait()
            .expect("Agent remains alive before shutdown")
            .is_none()
    );
    stop_agent(&mut agent).await;
}
