use hostlink_agent::{AgentConfig, ssh};
use russh::client::{self, Handler};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
fn private_windows_test_path(path: &std::path::Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};
    let current = windows_permissions::utilities::current_process_sid()
        .expect("current user token for fixture");
    let sid = ConvertSidToStringSid(&current).expect("SID string");
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{flags};FA;;;{})", sid.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().expect("protected fixture DACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(current.as_ref()),
        None,
        Some(descriptor.dacl().expect("DACL")),
        None,
    )
    .expect("apply current-user-only private test fixture ACL");
}

struct Pin(russh::keys::PublicKey);
impl Handler for Pin {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(key.certificate().is_none()
            && key.public_key().algorithm() == Algorithm::Ed25519
            && key.public_key().key_data() == self.0.key_data())
    }
}

async fn connect(addr: SocketAddr, host_key: &russh::keys::PublicKey) -> client::Handle<Pin> {
    client::connect(
        Arc::new(client::Config::default()),
        addr,
        Pin(host_key.clone()),
    )
    .await
    .expect("connect to embedded SSH server")
}

async fn authenticate(session: &mut client::Handle<Pin>, key: PrivateKey) -> bool {
    session
        .authenticate_publickey("agent", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .expect("controller authentication result")
        .success()
}

async fn job_request(session: &mut client::Handle<Pin>, bytes: &[u8]) -> Vec<u8> {
    let mut channel = session
        .channel_open_session()
        .await
        .expect("open jobs channel");
    channel
        .request_subsystem(true, "hostlink-jobs-v1")
        .await
        .expect("request jobs subsystem");
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("jobs subsystem rejected request"),
            Some(_) => {}
            None => panic!("jobs subsystem channel closed before acceptance"),
        }
    }
    let length = u32::try_from(bytes.len()).expect("request length");
    channel
        .data(&length.to_be_bytes()[..])
        .await
        .expect("write request header");
    channel.data(bytes).await.expect("write request body");
    channel.eof().await.expect("finish request");
    let mut frame = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => frame.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("jobs response deadline");
    assert!(frame.len() >= 4, "server returned a framed response");
    let size = u32::from_be_bytes(frame[..4].try_into().expect("response length")) as usize;
    assert_eq!(size, frame.len() - 4, "complete response frame");
    frame[4..].to_vec()
}

fn framed_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize jobs request")
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, fields)) = stat.rsplit_once(')') else {
        return false;
    };
    !fields.trim_start().starts_with("Z ")
}

#[tokio::test]
async fn loopback_auth_and_exec_keep_binary_streams_and_exit_status() {
    let temp = tempfile::tempdir().expect("temporary directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private fixture owner directory");
    }
    #[cfg(windows)]
    private_windows_test_path(temp.path(), true);
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
    let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong key");
    let host_path = temp.path().join("host_key");
    let auth_path = temp.path().join("authorized_keys");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    #[cfg(windows)]
    private_windows_test_path(&jobs, true);
    let pem = host
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("encode host key");
    std::fs::write(&host_path, pem.as_bytes()).expect("write host key");
    #[cfg(windows)]
    private_windows_test_path(&host_path, false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600))
            .expect("private host key");
        std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700))
            .expect("private jobs root");
    }
    let authorized = controller
        .public_key()
        .to_openssh()
        .expect("encode authorized key");
    std::fs::write(&auth_path, format!("{authorized} test-controller\n"))
        .expect("write authorized keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))
            .expect("private authorized_keys fixture");
    }
    #[cfg(windows)]
    private_windows_test_path(&auth_path, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("prebind loopback listener");
    let listen = listener.local_addr().expect("bound address");
    let cfg = AgentConfig {
        listen,
        user: "agent".into(),
        host_key: host_path,
        authorized_keys: auth_path,
        jobs_root: jobs.clone(),
        gateway: None,
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &cfg, async {
            let _ = shutdown.await;
        })
        .await
    });
    let host_public = host.public_key().clone();
    let wrong_host_pin = client::connect(
        Arc::new(client::Config::default()),
        listen,
        Pin(wrong.public_key().clone()),
    )
    .await;
    assert!(
        wrong_host_pin.is_err(),
        "host-key mismatch must reject the SSH connection"
    );
    let mut session = connect(listen, &host_public).await;
    assert!(
        !session
            .authenticate_publickey(
                "wrong-user",
                PrivateKeyWithHashAlg::new(Arc::new(controller.clone()), None)
            )
            .await
            .expect("wrong username auth result")
            .success()
    );
    session
        .disconnect(Disconnect::ByApplication, "negative auth complete", "en")
        .await
        .expect("disconnect after negative auth");

    let mut rejected = connect(listen, &host_public).await;
    let auth = rejected
        .authenticate_publickey("agent", PrivateKeyWithHashAlg::new(Arc::new(wrong), None))
        .await
        .expect("wrong key auth result");
    assert!(!auth.success());
    rejected
        .disconnect(Disconnect::ByApplication, "negative auth complete", "en")
        .await
        .expect("disconnect after wrong key");

    let mut session = connect(listen, &host_public).await;
    let auth = session
        .authenticate_publickey(
            "agent",
            PrivateKeyWithHashAlg::new(Arc::new(controller), None),
        )
        .await
        .expect("controller authentication");
    assert!(auth.success());
    let mut channel = session
        .channel_open_session()
        .await
        .expect("open session channel");
    channel
        .exec(true, {
            #[cfg(unix)]
            { r"cat; printf '\000\377' >&2; exit 7" }
            #[cfg(windows)]
            { r"$i=[Console]::OpenStandardInput();$o=[Console]::OpenStandardOutput();$b=New-Object byte[] 1024;while(($n=$i.Read($b,0,$b.Length))-gt 0){$o.Write($b,0,$n)};$o.Flush();$e=[Console]::OpenStandardError();$x=[byte[]](0,255);$e.Write($x,0,2);$e.Flush();exit 7" }
        })
        .await
        .expect("request exec");
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("exec request rejected"),
            Some(_) => {}
            None => panic!("channel ended before exec acknowledgement"),
        }
    }
    let input = [0_u8, 1, 127, 128, 255];
    channel.data(&input[..]).await.expect("send binary stdin");
    channel.eof().await.expect("close stdin");
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut exit, mut eof, mut close) = (None, false, false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !close {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
                Some(ChannelMsg::Eof) => eof = true,
                Some(ChannelMsg::Close) => close = true,
                Some(_) => {}
                None => break,
            }
        }
    })
    .await
    .expect("exec output deadline");
    assert_eq!(stdout, input);
    assert_eq!(stderr, [0_u8, 255]);
    assert_eq!(exit, Some(7));
    assert!(eof && close);
    session
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect");
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("server shutdown deadline")
        .expect("server task")
        .expect("server result");
}

#[cfg(unix)]
#[tokio::test]
async fn jobs_subsystem_survives_disconnect_and_reconnects_without_relaunch() {
    use sha2::{Digest as _, Sha256};

    let temp = tempfile::tempdir().expect("temporary directory");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
    }
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
    let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("wrong key");
    let host_path = temp.path().join("host_key");
    let auth_path = temp.path().join("authorized_keys");
    let jobs = temp.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    let pem = host
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("encode host key");
    std::fs::write(&host_path, pem.as_bytes()).expect("write host key");
    let authorized = controller
        .public_key()
        .to_openssh()
        .expect("encode controller key");
    std::fs::write(&auth_path, format!("{authorized} test-controller\n")).expect("authorized key");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600))
            .expect("private host key");
        std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))
            .expect("private auth file");
        std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700))
            .expect("private jobs root");
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let listen = listener.local_addr().expect("listener address");
    let config = AgentConfig {
        listen,
        user: "agent".into(),
        host_key: host_path,
        authorized_keys: auth_path,
        jobs_root: jobs.clone(),
        gateway: None,
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = shutdown.await;
        })
        .await
    });

    let host_public = host.public_key().clone();
    let mut denied = connect(listen, &host_public).await;
    assert!(
        !authenticate(&mut denied, wrong).await,
        "unauthorized key is rejected"
    );
    denied
        .disconnect(Disconnect::ByApplication, "negative auth", "en")
        .await
        .expect("close denied session");

    let mut session = connect(listen, &host_public).await;
    assert!(authenticate(&mut session, controller.clone()).await);
    let malformed = job_request(&mut session, b"{broken json").await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&malformed).unwrap()["ok"],
        false
    );

    let id = uuid::Uuid::new_v4().to_string();
    let executable = temp.path().join("pinned-sh");
    std::fs::copy(
        std::fs::canonicalize("/bin/sh").expect("resolve shell executable"),
        &executable,
    )
    .expect("stage private source-pinned executable");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
            .expect("make staged executable read-only");
    }
    let source_sha256 = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&executable).expect("read pinned executable"))
    );
    let start = serde_json::json!({
        "version": 1,
        "op": "start",
        "id": id,
        "spec": {
            "program": executable,
            "args": ["-c", "printf x >> launch-count; sleep 1; printf '\\000\\377'; printf '\\377E' >&2; exit 7"],
            "cwd": temp.path(),
            "source_sha256": source_sha256
        }
    });
    let accepted = job_request(&mut session, &framed_json(&start)).await;
    let accepted: serde_json::Value = serde_json::from_slice(&accepted).expect("parse start ack");
    assert_eq!(accepted["ok"], true);
    assert_eq!(accepted["id"], id);
    session
        .disconnect(
            Disconnect::ByApplication,
            "simulate lost SSH connection",
            "en",
        )
        .await
        .expect("drop original session");

    let mut resumed = connect(listen, &host_public).await;
    assert!(authenticate(&mut resumed, controller.clone()).await);
    let status_request = serde_json::json!({"version":1,"op":"status","id":id});
    let mut status: serde_json::Value =
        serde_json::from_slice(&job_request(&mut resumed, &framed_json(&status_request)).await)
            .expect("status response");
    for _ in 0..40 {
        if status["state"]["state"] == "exited" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        status =
            serde_json::from_slice(&job_request(&mut resumed, &framed_json(&status_request)).await)
                .expect("poll status");
    }
    assert_eq!(status["state"]["state"], "exited");
    assert_eq!(status["state"]["code"], 7);

    let output_request =
        serde_json::json!({"version":1,"op":"output","id":id,"stream":"stdout","offset":0});
    let output: serde_json::Value =
        serde_json::from_slice(&job_request(&mut resumed, &framed_json(&output_request)).await)
            .expect("stdout response");
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(output["data_base64"].as_str().unwrap())
            .unwrap(),
        [0_u8, 255]
    );
    assert_eq!(output["eof"], true);
    let stderr_request =
        serde_json::json!({"version":1,"op":"output","id":id,"stream":"stderr","offset":0});
    let stderr: serde_json::Value =
        serde_json::from_slice(&job_request(&mut resumed, &framed_json(&stderr_request)).await)
            .expect("stderr response");
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(stderr["data_base64"].as_str().unwrap())
            .unwrap(),
        [255_u8, b'E']
    );

    let duplicate = job_request(&mut resumed, &framed_json(&start)).await;
    let duplicate: serde_json::Value =
        serde_json::from_slice(&duplicate).expect("duplicate response");
    assert_eq!(duplicate["ok"], true);
    assert_eq!(
        duplicate["state"]["code"], 7,
        "same ID returns the original terminal job"
    );
    assert_eq!(
        std::fs::read_to_string(temp.path().join("launch-count")).expect("launch marker"),
        "x"
    );

    let overflow_id = uuid::Uuid::new_v4().to_string();
    let overflow_start = serde_json::json!({
        "version": 1,
        "op": "start",
        "id": overflow_id,
        "spec": {
            "program": executable,
            "args": ["-c", "head -c 8388609 /dev/zero"],
            "cwd": temp.path(),
            "source_sha256": source_sha256
        }
    });
    let overflow_ack: serde_json::Value =
        serde_json::from_slice(&job_request(&mut resumed, &framed_json(&overflow_start)).await)
            .expect("overflow job ack");
    assert_eq!(overflow_ack["ok"], true);
    let overflow_status_request = serde_json::json!({"version":1,"op":"status","id":overflow_id});
    let mut overflow_status: serde_json::Value = serde_json::from_slice(
        &job_request(&mut resumed, &framed_json(&overflow_status_request)).await,
    )
    .expect("overflow job status");
    for _ in 0..100 {
        if overflow_status["state"]["state"] != "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        overflow_status = serde_json::from_slice(
            &job_request(&mut resumed, &framed_json(&overflow_status_request)).await,
        )
        .expect("poll overflow job");
    }
    assert_eq!(overflow_status["state"]["state"], "failed");
    assert_eq!(
        std::fs::metadata(jobs.join(&overflow_id).join("stdout.bin"))
            .expect("bounded overflow log")
            .len(),
        8 * 1024 * 1024
    );

    let tree_id = uuid::Uuid::new_v4().to_string();
    let tree_start = serde_json::json!({
        "version": 1,
        "op": "start",
        "id": tree_id,
        "spec": {
            "program": executable,
            "args": ["-c", "sleep 300 & echo $! > descendant-pid; wait"],
            "cwd": temp.path(),
            "source_sha256": source_sha256
        }
    });
    let tree_ack: serde_json::Value =
        serde_json::from_slice(&job_request(&mut resumed, &framed_json(&tree_start)).await)
            .expect("process tree job ack");
    assert_eq!(tree_ack["ok"], true);
    let pid_path = temp.path().join("descendant-pid");
    for _ in 0..100 {
        if pid_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let descendant_pid: u32 = std::fs::read_to_string(&pid_path)
        .expect("child process wrote descendant pid")
        .trim()
        .parse()
        .expect("valid descendant pid");
    resumed
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect");
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .expect("server shutdown")
        .expect("server task")
        .expect("server result");
    for _ in 0..100 {
        if !process_is_running(descendant_pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !process_is_running(descendant_pid),
        "Agent shutdown tears down the entire owned process group"
    );
}
