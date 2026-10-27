#![cfg(unix)]
//! Actual hostlink CLI -> pinned russh -> key-scoped SFTP -> Seal -> durable exec.
use hostlink_agent::{AgentConfig, ssh};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use tokio::process::Command;

fn privately_write(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn run_cli_seals_binary_and_idempotently_returns_exact_nonzero_exit() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let jobs = temp.path().join("jobs");
    fs::create_dir(&jobs).unwrap();
    fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).unwrap();
    hostlink_agent::durable::DurableStore::initialize_fresh(&jobs)
        .await
        .expect("initialize fresh private Agent SQLite fixture")
        .close()
        .await;

    let agent_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_key = temp.path().join("host-key");
    let identity = temp.path().join("controller-key");
    let authorized = temp.path().join("authorized-keys");
    privately_write(
        &host_key,
        agent_key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    privately_write(
        &identity,
        controller_key
            .to_openssh(LineEnding::LF)
            .unwrap()
            .as_bytes(),
    );
    privately_write(
        &authorized,
        format!(
            "{} test-owner\n",
            controller_key.public_key().to_openssh().unwrap()
        )
        .as_bytes(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let config = AgentConfig {
        listen: endpoint,
        user: "hostlink".into(),
        host_key,
        authorized_keys: authorized,
        jobs_root: jobs,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = stop_rx.await;
        })
        .await
    });
    let host_config = temp.path().join("host.json");
    privately_write(
        &host_config,
        serde_json::to_string(&serde_json::json!({
            "endpoint":endpoint.to_string(),
            "user":"hostlink",
            "identity":identity.to_str().unwrap(),
            "host_public_key":agent_key.public_key().to_openssh().unwrap(),
            "gateway":null
        }))
        .unwrap()
        .as_bytes(),
    );

    let source = fs::canonicalize("/bin/sh").expect("source-exact local executable");
    let id = uuid::Uuid::new_v4().to_string();
    let marker = temp.path().join("launches");
    let script = format!(
        "printf x >> '{}'; printf '\\000\\377'; printf '\\377E' >&2; exit 7",
        marker.display()
    );
    let bin = env!("CARGO_BIN_EXE_hostlink");

    for attempt in 0..2 {
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            Command::new(bin)
                .arg("run")
                .arg("--config")
                .arg(&host_config)
                .arg("--binary")
                .arg(&source)
                .arg("--id")
                .arg(&id)
                .arg("--")
                .arg("-c")
                .arg(&script)
                .output(),
        )
        .await
        .expect("CLI run deadline")
        .expect("CLI process");
        assert_eq!(
            result.status.code(),
            Some(7),
            "attempt {attempt}, stdout={:?}, stderr={:?}",
            result.stdout,
            result.stderr,
        );
        assert_eq!(result.stdout, [0, 255], "raw stdout changed");
        assert!(
            result.stderr.windows(2).any(|window| window == [255, b'E']),
            "raw stderr unavailable"
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(&id), "UUID must be visible before start");
        assert_eq!(
            fs::read(&marker).unwrap(),
            b"x",
            "same job ID must not duplicate remote side effects"
        );
    }

    let conflicting = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new(bin)
            .arg("run")
            .arg("--config")
            .arg(&host_config)
            .arg("--binary")
            .arg(&source)
            .arg("--id")
            .arg(&id)
            .arg("--")
            .arg("-c")
            .arg("printf must-not-run")
            .output(),
    )
    .await
    .expect("conflicting run deadline")
    .expect("CLI process");
    assert!(!conflicting.status.success());
    assert!(conflicting.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&conflicting.stderr);
    assert!(diagnostic.contains("run outcome UNKNOWN during start"));
    assert!(diagnostic.contains("do not rerun or resend start"));
    assert!(diagnostic.contains(&id));
    assert_eq!(fs::read(&marker).unwrap(), b"x");

    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("server shutdown deadline")
        .expect("join Agent")
        .expect("Agent shutdown");
}
