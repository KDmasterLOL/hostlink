#![cfg(unix)]

use hostlink_agent::{AgentConfig, ssh};
use russh::client::{self, Handler};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::protocol::OpenFlags;
use sha2::{Digest as _, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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

async fn connect(addr: SocketAddr, host: &russh::keys::PublicKey) -> client::Handle<Pin> {
    client::connect(Arc::new(client::Config::default()), addr, Pin(host.clone()))
        .await
        .expect("connect to loopback Agent")
}

async fn authenticate(session: &mut client::Handle<Pin>, key: PrivateKey) {
    assert!(
        session
            .authenticate_publickey("agent", PrivateKeyWithHashAlg::new(Arc::new(key), None))
            .await
            .expect("public key authentication")
            .success()
    );
}

async fn jobs_request(
    session: &mut client::Handle<Pin>,
    request: &serde_json::Value,
) -> serde_json::Value {
    let mut channel = session.channel_open_session().await.expect("jobs channel");
    channel
        .request_subsystem(true, "hostlink-jobs-v1")
        .await
        .expect("jobs subsystem request");
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => panic!("jobs subsystem rejected request"),
            Some(_) => {}
            None => panic!("jobs channel closed before acceptance"),
        }
    }
    let body = serde_json::to_vec(request).expect("request JSON");
    channel
        .data(&(body.len() as u32).to_be_bytes()[..])
        .await
        .expect("frame header");
    channel.data(&body[..]).await.expect("frame body");
    channel.eof().await.expect("request EOF");
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
    .expect("jobs response timeout");
    assert!(frame.len() >= 4);
    let len = u32::from_be_bytes(frame[..4].try_into().expect("response frame")) as usize;
    assert_eq!(len, frame.len() - 4);
    serde_json::from_slice(&frame[4..]).expect("response JSON")
}

async fn open_sftp(session: &client::Handle<Pin>) -> russh_sftp::client::SftpSession {
    let channel = session.channel_open_session().await.expect("SFTP channel");
    channel
        .request_subsystem(true, "sftp")
        .await
        .expect("SFTP subsystem request");
    russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .expect("SFTP session")
}

async fn upload(session: &client::Handle<Pin>, name: &str, bytes: &[u8], phase: &str) {
    let sftp = open_sftp(session).await;
    let mut file = sftp
        .open_with_flags(
            name.to_owned(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
        )
        .await
        .expect("create-only upload");
    file.write_all(bytes).await.unwrap_or_else(|error| {
        panic!(
            "{phase}: SFTP upload write failed for {} bytes ({error:?})",
            bytes.len()
        )
    });
    file.close().await.expect("close upload");
    sftp.close().await.expect("close SFTP");
}

#[tokio::test]
async fn controller_scoped_upload_seal_and_durable_exit_seven() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("fixture root");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private fixture root");
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let first = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("first controller");
    let second =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("second controller");
    let host_path = temp.path().join("host_key");
    let auth_path = temp.path().join("authorized_keys");
    let jobs_root = temp.path().join("jobs");
    std::fs::create_dir(&jobs_root).expect("jobs root");
    std::fs::set_permissions(&jobs_root, std::fs::Permissions::from_mode(0o700))
        .expect("private jobs root");
    hostlink_agent::durable::DurableStore::initialize_fresh(&jobs_root)
        .await
        .expect("initialize fresh private Agent SQLite fixture")
        .close()
        .await;
    std::fs::write(
        &host_path,
        host.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("host key PEM"),
    )
    .expect("write host key");
    std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600))
        .expect("private host key");
    let first_public = first.public_key().to_openssh().expect("first public key");
    let second_public = second.public_key().to_openssh().expect("second public key");
    std::fs::write(
        &auth_path,
        format!("{first_public} first\n{second_public} second\n"),
    )
    .expect("authorized controller keys");
    std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))
        .expect("private authorized keys");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let listen = listener.local_addr().expect("listener address");
    let config = AgentConfig {
        listen,
        user: "agent".into(),
        host_key: host_path,
        authorized_keys: auth_path,
        jobs_root: jobs_root.clone(),
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        ssh::serve_on(listener, &config, async {
            let _ = shutdown.await;
        })
        .await
    });

    let mut owner = connect(listen, host.public_key()).await;
    authenticate(&mut owner, first.clone()).await;
    let bytes = std::fs::read("/bin/sh").expect("Linux shell source");
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let upload_name = format!("{sha256}.upload");
    upload(&owner, &upload_name, &bytes, "initial upload").await;

    let stale_sftp = open_sftp(&owner).await;
    let stale_handle = stale_sftp
        .open(upload_name.clone())
        .await
        .expect("open candidate before replacement");
    stale_sftp
        .remove_file(upload_name.clone())
        .await
        .expect("unlink open candidate");
    let mut replacement_session = connect(listen, host.public_key()).await;
    authenticate(&mut replacement_session, first.clone()).await;
    let mut replacement = bytes.clone();
    replacement[0] ^= 1;
    upload(
        &replacement_session,
        &upload_name,
        &replacement,
        "file-replacement race upload",
    )
    .await;
    let replace_race = jobs_request(
        &mut replacement_session,
        &serde_json::json!({"version":1,"op":"seal","name":upload_name,"sha256":sha256,"size":bytes.len()}),
    )
    .await;
    assert_eq!(
        replace_race["ok"], false,
        "replacement bytes cannot pass the seal hash"
    );
    stale_handle
        .close()
        .await
        .expect("close stale upload handle");
    stale_sftp.close().await.expect("close stale SFTP session");
    let owner_sftp = open_sftp(&replacement_session).await;
    owner_sftp
        .remove_file(upload_name.clone())
        .await
        .expect("remove replacement candidate");
    owner_sftp.close().await.expect("close owner SFTP");
    upload(
        &replacement_session,
        &upload_name,
        &bytes,
        "restored valid upload",
    )
    .await;
    replacement_session
        .disconnect(Disconnect::ByApplication, "replace test complete", "en")
        .await
        .expect("disconnect replacement session");

    let mut other = connect(listen, host.public_key()).await;
    authenticate(&mut other, second).await;
    let other_sftp = open_sftp(&other).await;
    assert!(other_sftp.read(upload_name.clone()).await.is_err());
    assert!(other_sftp.remove_file(upload_name.clone()).await.is_err());
    assert!(other_sftp.read(format!("../{upload_name}")).await.is_err());
    assert!(
        other_sftp
            .open_with_flags(
                format!("../{upload_name}"),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .is_err()
    );
    assert!(
        other_sftp
            .symlink(upload_name.clone(), "../owner/uploads/escape.upload")
            .await
            .is_err()
    );
    other_sftp.close().await.expect("close second SFTP");

    let owner_sftp = open_sftp(&owner).await;
    owner_sftp
        .remove_file(upload_name.clone())
        .await
        .expect("remove owner candidate");
    owner_sftp.close().await.expect("close owner SFTP");
    upload(
        &owner,
        &upload_name,
        &bytes[..bytes.len() / 2],
        "partial upload",
    )
    .await;
    let partial = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"seal","name":upload_name,"sha256":sha256,"size":bytes.len()}),
    )
    .await;
    assert_eq!(
        partial["ok"], false,
        "partial upload cannot be sealed: {partial}"
    );
    let owner_sftp = open_sftp(&owner).await;
    owner_sftp
        .remove_file(upload_name.clone())
        .await
        .expect("remove partial upload");
    owner_sftp.close().await.expect("close owner SFTP");
    let mut corrupted = bytes.clone();
    corrupted[0] ^= 1;
    upload(&owner, &upload_name, &corrupted, "corrupt upload").await;
    let corrupt_ack = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"seal","name":upload_name,"sha256":sha256,"size":bytes.len()}),
    )
    .await;
    assert_eq!(
        corrupt_ack["ok"], false,
        "corrupted upload cannot be sealed: {corrupt_ack}"
    );
    let owner_sftp = open_sftp(&owner).await;
    owner_sftp
        .remove_file(upload_name.clone())
        .await
        .expect("remove corrupted upload");
    owner_sftp.close().await.expect("close owner SFTP");
    upload(&owner, &upload_name, &bytes, "final valid upload").await;
    let sealed = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"seal","name":upload_name,"sha256":sha256,"size":bytes.len()}),
    )
    .await;
    assert_eq!(
        sealed
            .as_object()
            .expect("seal response")
            .keys()
            .collect::<Vec<_>>(),
        vec!["ok", "program", "sha256", "version"]
    );
    assert_eq!(sealed["ok"], true);
    assert_eq!(sealed["sha256"], sha256);
    let program = sealed["program"].as_str().expect("Agent canonical program");
    assert!(program.ends_with(&format!("{sha256}.program")));
    assert_eq!(
        std::fs::read(program).expect("sealed artifact bytes"),
        bytes
    );
    assert_eq!(
        std::fs::metadata(program)
            .expect("sealed metadata")
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    let repeated = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"seal","name":upload_name,"sha256":sha256,"size":bytes.len()}),
    )
    .await;
    assert_eq!(repeated, sealed, "exact repeat seal is stable");

    let id = uuid::Uuid::new_v4().to_string();
    let start = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"start","id":id,"spec":{"program":program,"args":["-c","exit 7"],"cwd":temp.path(),"source_sha256":sha256}}),
    )
    .await;
    assert_eq!(start["ok"], true);
    for _ in 0..100 {
        let status = jobs_request(
            &mut owner,
            &serde_json::json!({"version":1,"op":"status","id":id}),
        )
        .await;
        if status["state"]["state"] == "exited" {
            assert_eq!(status["state"]["code"], 7);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let status = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"status","id":id}),
    )
    .await;
    assert_eq!(status["state"]["state"], "exited");
    assert_eq!(status["state"]["code"], 7);
    let output = jobs_request(
        &mut owner,
        &serde_json::json!({"version":1,"op":"output","id":id,"stream":"stdout","offset":0}),
    )
    .await;
    assert_eq!(output["ok"], true);

    owner
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect");
    other
        .disconnect(Disconnect::ByApplication, "test complete", "en")
        .await
        .expect("disconnect");
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server shutdown deadline")
        .expect("server task")
        .expect("server result");
}
