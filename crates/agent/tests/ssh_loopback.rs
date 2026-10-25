use hostlink_agent::{AgentConfig, ssh};
use russh::client::{self, Handler};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("prebind loopback listener");
    let listen = listener.local_addr().expect("bound address");
    let cfg = AgentConfig {
        listen,
        user: "agent".into(),
        host_key: host_path,
        authorized_keys: auth_path,
        jobs_root: jobs,
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
        .exec(true, "cat; printf '\\000\\377' >&2; exit 7")
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
