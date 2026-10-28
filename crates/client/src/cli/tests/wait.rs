//! Real pinned SSH transport: status/stdout succeed, stderr channel opens fail.
use super::*;
use russh::{
    Channel, ChannelId, ChannelOpenFailure,
    keys::{Algorithm, PrivateKey, PublicKey, ssh_key::LineEnding},
    server::{self, Auth, Msg, Session},
};
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Script {
    key: PublicKey,
    opened: usize,
    channels: HashMap<ChannelId, Channel<Msg>>,
    failures: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl server::Handler for Script {
    type Error = russh::Error;
    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if key == &self.key {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.opened += 1;
        if self.opened == 3 {
            self.failures.fetch_add(1, Ordering::SeqCst);
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        } else {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        }
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(name, "hostlink-jobs");
        session.channel_success(id)?;
        let channel = self.channels.remove(&id).unwrap();
        let requests = self.requests.clone();
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let length = stream.read_u32().await.unwrap() as usize;
            assert!(length < 65536);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            requests.fetch_add(1, Ordering::SeqCst);
            let output = request["op"] == "logs";
            if output {
                assert_eq!(request["stream"], "stdout");
            } else {
                assert_eq!(request["op"], "status");
            }
            let response = json!({"ok":true,"id":request["id"],"state":{"state":"running"},
                "data_base64":if output { json!("") } else { json!(null) },
                "next_offset":if output { json!(0) } else { json!(null) },
                "eof":if output { json!(false) } else { json!(null) }});
            let bytes = serde_json::to_vec(&response).unwrap();
            stream.write_u32(bytes.len() as u32).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        Ok(())
    }
}

#[tokio::test]
async fn successful_status_and_stdout_cannot_reset_stderr_retry_budget() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let identity_file = root.path().join("identity");
    fs::write(
        &identity_file,
        identity.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    fs::set_permissions(&identity_file, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spec = HostSpec {
        endpoint: listener.local_addr().unwrap(),
        user: "fixture".into(),
        identity: identity_file,
        host_public_key: host.public_key().to_openssh().unwrap(),
        gateway: None,
    };
    let failures = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let server_failures = failures.clone();
    let server_requests = requests.clone();
    let server = tokio::spawn(async move {
        let config = Arc::new(server::Config {
            keys: vec![host],
            ..Default::default()
        });
        let mut sessions = tokio::task::JoinSet::new();
        // Exactly initial connection + three permitted reconnects.
        for _ in 0..4 {
            let (stream, _) = listener.accept().await.unwrap();
            let handler = Script {
                key: identity.public_key().clone(),
                opened: 0,
                channels: HashMap::new(),
                failures: server_failures.clone(),
                requests: server_requests.clone(),
            };
            let session = server::run_stream(config.clone(), stream, handler)
                .await
                .unwrap();
            sessions.spawn(async move {
                session.await.unwrap();
            });
        }
        while sessions.join_next().await.is_some() {}
    });
    let mut client = HostConnection::connect(&spec).await.unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        wait_for_job(
            &mut client,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            &spec,
            "--config fixture",
        ),
    )
    .await;
    client.close().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    let error = result
        .expect("wait must exhaust its retry budget")
        .unwrap_err()
        .to_string();
    assert!(error.contains("output reattach"), "{error}");
    assert_eq!(failures.load(Ordering::SeqCst), 4);
    assert_eq!(requests.load(Ordering::SeqCst), 8);
}
