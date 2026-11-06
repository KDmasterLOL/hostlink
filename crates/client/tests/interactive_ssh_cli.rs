//! End-to-end Controller executable -> pinned embedded Agent -> native PTY.
#![cfg(target_os = "linux")]

use hostlink_agent::{AgentConfig, jobs::JobStore, ssh};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::{os::unix::fs::PermissionsExt, path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

fn private_file(path: &Path, data: impl AsRef<[u8]>) {
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[tokio::test]
async fn source_controller_ssh_opens_and_exits_real_managed_pty_shell() {
    // This fixture does not touch the installed Agent, authoritative Hub,
    // Gateways, user SSH config, customer processes, or infobases.
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
    JobStore::initialize_fresh(&jobs)
        .await
        .unwrap()
        .close()
        .await;

    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_key = temp.path().join("host_key");
    let authorized_keys = temp.path().join("authorized_keys");
    let controller_key = temp.path().join("controller_key");
    private_file(&host_key, host.to_openssh(LineEnding::LF).unwrap());
    private_file(
        &controller_key,
        controller.to_openssh(LineEnding::LF).unwrap(),
    );
    private_file(
        &authorized_keys,
        controller.public_key().to_openssh().unwrap(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cfg = AgentConfig {
        listen: address,
        user: "agent".into(),
        host_key,
        authorized_keys,
        jobs_root: jobs,
        board_listen: None,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &cfg, async {
            let _ = shutdown.await;
        })
        .await
    });
    let direct_config = temp.path().join("host.json");
    private_file(
        &direct_config,
        serde_json::to_vec(&serde_json::json!({
            "endpoint": address,
            "user": "agent",
            "identity": controller_key,
            "host_public_key": host.public_key().to_openssh().unwrap(),
            "gateway": null
        }))
        .unwrap(),
    );

    // Util-linux script creates a real LOCAL terminal for the raw-mode guard.
    // The REMOTE PTY is opened by the real authenticated Agent SSH server.
    let command = format!(
        "{} ssh --config {}",
        shell_quote(env!("CARGO_BIN_EXE_hostlink")),
        shell_quote(direct_config.to_str().unwrap()),
    );
    let mut client = Command::new("script")
        // util-linux script uses $SHELL for its -c command; run the POSIX
        // fixture quoting under sh rather than the operator's Nushell.
        .env("SHELL", "/bin/sh")
        .args(["-q", "-e", "-c", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("launch disposable local PTY for HostLink Controller");
    let mut input = client.stdin.take().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    if let Err(error) = input
        .write_all(b"echo hostlink-cli-native-marker\nexit 7\n")
        .await
    {
        drop(input);
        let details = client.wait_with_output().await.unwrap();
        panic!(
            "failed to write into local terminal: {error}; child code={:?}; stdout={}; stderr={}",
            details.status.code(),
            String::from_utf8_lossy(&details.stdout),
            String::from_utf8_lossy(&details.stderr),
        );
    }
    input.flush().await.unwrap();

    let output = tokio::time::timeout(Duration::from_secs(22), client.wait_with_output())
        .await
        .expect("interactive CLI did not exit within 22 seconds")
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.code() == Some(7),
        "remote shell exit7 was not propagated: status={:?}, output={text}, stderr={error}",
        output.status,
    );
    assert!(
        text.contains("hostlink-cli-native-marker"),
        "remote shell output missing: {text}"
    );
    drop(input);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(8), server)
        .await
        .expect("disposable Agent did not stop")
        .unwrap()
        .unwrap();
}
