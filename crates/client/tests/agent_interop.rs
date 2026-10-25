//! End-to-end integration of the two actual rewrite packages over a loopback TCP socket.

use hostlink::{HostSpec, connect::HostConnection};
use hostlink_agent::{AgentConfig, ssh};
use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
use std::fs;
use std::time::Duration;

fn private_file(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).expect("write private test key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private test key ACL");
    }
}

fn private_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private directory ACL");
    }
}

#[tokio::test]
async fn agent_and_controller_authenticate_stream_execute_and_transfer() {
    let root = tempfile::tempdir().expect("disposable integration dir");
    private_directory(root.path());
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("random host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("random controller key");

    let host_key = root.path().join("host-key");
    let identity = root.path().join("controller-key");
    let authorized_keys = root.path().join("authorized_keys");
    let jobs_root = root.path().join("jobs");
    fs::create_dir(&jobs_root).expect("jobs root");
    private_directory(&jobs_root);
    private_file(
        &host_key,
        host.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    private_file(
        &identity,
        controller.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    );
    private_file(
        &authorized_keys,
        format!(
            "{} controller@disposable\n",
            controller.public_key().to_openssh().unwrap()
        )
        .as_bytes(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let config = AgentConfig {
        listen: endpoint,
        user: "hostlink".into(),
        host_key,
        authorized_keys,
        jobs_root,
        gateway: None,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = stop_rx.await;
        })
        .await
    });

    let expected = host.public_key().to_openssh().unwrap();
    let spec = HostSpec {
        endpoint,
        user: "hostlink".into(),
        identity,
        host_public_key: expected,
        gateway: None,
    };
    let mut host = tokio::time::timeout(Duration::from_secs(15), HostConnection::connect(&spec))
        .await
        .expect("connect timeout")
        .expect("SSH host key authentication");
    #[cfg(unix)]
    let command = r"cat; printf '\000\377' >&2; exit 7";
    #[cfg(windows)]
    let command = r"$s=[Console]::OpenStandardInput();$o=[Console]::OpenStandardOutput();$b=New-Object byte[] 1024;while(($n=$s.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n)};$o.Flush();$e=[Console]::OpenStandardError();$x=[byte[]](0,255);$e.Write($x,0,2);$e.Flush();exit 7";
    let payload: Vec<u8> = (0..8192).map(|i| (i * 37) as u8).collect();
    let result = host
        .exec(command, &payload)
        .await
        .expect("SSH exec round trip");
    assert_eq!(result.stdout, payload, "raw stdout was corrupted");
    assert_eq!(
        result.stderr,
        [0_u8, 255],
        "raw stderr channel was corrupted"
    );
    assert_eq!(result.exit_code, 7, "remote nonzero status was lost");

    let contents = b"hostlink-russh-private-sftp\x00\xff";
    host.sftp_upload("integration.bin", contents)
        .await
        .expect("SFTP create");
    assert!(
        host.sftp_upload("integration.bin", b"overwrite")
            .await
            .is_err()
    );
    let downloaded = host
        .sftp_download("integration.bin")
        .await
        .expect("SFTP download");
    assert_eq!(downloaded, contents);

    host.close().await.expect("SSH session close");
    stop_tx.send(()).expect("shutdown active Agent");
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("Agent stop deadline")
        .expect("Agent task join")
        .expect("Agent SSH server stopped");
}
