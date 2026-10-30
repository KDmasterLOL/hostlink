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
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", sid.to_string_lossy());
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
    hostlink_agent::jobs::JobStore::initialize_fresh(&jobs)
        .await
        .expect("initialize fresh private Agent SQLite fixture")
        .close()
        .await;
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
        board_listen: None,
        gateway: None,
        gateway_alternates: Vec::new(),
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
    let mut password = connect(listen, &host_public).await;
    let result = password
        .authenticate_password("agent", "not-a-password")
        .await
        .expect("password authentication response");
    match result {
        client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => {
            assert_eq!(&*remaining_methods, &[russh::MethodKind::PublicKey]);
            assert!(!partial_success);
        }
        client::AuthResult::Success => panic!("SSH must use public-key authentication only"),
    }
    password
        .disconnect(Disconnect::ByApplication, "password rejected", "en")
        .await
        .expect("disconnect after password rejection");
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
    let mut removed = session.channel_open_session().await.unwrap();
    removed
        .request_subsystem(true, "hostlink-jobs")
        .await
        .unwrap();
    loop {
        match removed.wait().await {
            Some(ChannelMsg::Failure) => break,
            Some(ChannelMsg::Success) | None => {
                panic!("removed jobs subsystem accepted or closed without refusal")
            }
            _ => {}
        }
    }
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
