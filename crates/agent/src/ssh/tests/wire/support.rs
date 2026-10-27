use super::*;
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::os::unix::fs::PermissionsExt;

pub(super) struct Pin(PublicKey);
impl client::Handler for Pin {
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

pub(super) struct WireFixture {
    pub(super) root: tempfile::TempDir,
    pub(super) jobs: Arc<JobRuntime>,
    pub(super) keys: [PrivateKey; 2],
    host: PrivateKey,
    clients: Vec<client::Handle<Pin>>,
    sessions: tokio::task::JoinSet<Result<(), russh::Error>>,
}

impl WireFixture {
    pub(super) async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join("jobs");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = DurableStore::initialize_fresh(state).await.unwrap();
        let runner = store.acquire_runner().unwrap();
        let jobs = Arc::new(JobRuntime {
            store,
            _runner: runner,
            start_lock: Mutex::new(()),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE_JOBS)),
            channel_slots: Arc::new(Semaphore::new(MAX_JOB_CHANNELS)),
            accepting: AtomicBool::new(true),
            shutdown: processkit::CancellationToken::new(),
            active_jobs: std::sync::Mutex::new(HashMap::new()),
        });
        Self {
            root,
            jobs,
            keys: std::array::from_fn(|_| {
                PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
            }),
            host: PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
            clients: Vec::new(),
            sessions: tokio::task::JoinSet::new(),
        }
    }

    pub(super) async fn connect(&mut self, key: usize) -> usize {
        // Use the actual production session handler over a memory stream. Only
        // the test's carrier plumbing differs from run_on_socket/connect TCP.
        let mut server = EmbeddedServer {
            expected_user: Arc::from("agent"),
            authorized_keys: Arc::new(
                self.keys
                    .iter()
                    .map(|key| key.public_key().clone())
                    .collect(),
            ),
            forward_slots: Arc::new(Semaphore::new(MAX_DIRECT_TCP_CHANNELS)),
            sftp_slots: Arc::new(Semaphore::new(MAX_ACTIVE_SFTP_SESSIONS)),
            exec_slots: Arc::new(Semaphore::new(MAX_ACTIVE_EXEC_SESSIONS)),
            exec_shutdown: processkit::CancellationToken::new(),
            jobs: self.jobs.clone(),
            connection_slots: Arc::new(Semaphore::new(MAX_AUTHENTICATED_SESSIONS)),
        };
        let handler = server.new_client(None);
        let config = Arc::new(russh::server::Config {
            keys: vec![self.host.clone()],
            ..Default::default()
        });
        let (server_stream, client_stream) = tokio::io::duplex(256 * 1024);
        self.sessions.spawn(async move {
            russh::server::run_stream(config, server_stream, handler)
                .await?
                .await
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            client::connect_stream(
                Arc::new(client::Config::default()),
                client_stream,
                Pin(self.host.public_key().clone()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "agent",
                    PrivateKeyWithHashAlg::new(Arc::new(self.keys[key].clone()), None,)
                )
                .await
                .unwrap()
                .success()
        );
        let index = self.clients.len();
        self.clients.push(client);
        index
    }

    pub(super) async fn disconnect(&self, client: usize) {
        self.clients[client]
            .disconnect(Disconnect::ByApplication, "wire fixture disconnect", "en")
            .await
            .unwrap();
    }

    pub(super) async fn send(
        &self,
        client: usize,
        request: &Value,
        extra_frame: bool,
    ) -> Channel<client::Msg> {
        let mut channel = self.clients[client].channel_open_session().await.unwrap();
        channel
            .request_subsystem(true, JOB_SUBSYSTEM)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => break,
                    Some(ChannelMsg::Failure) | None => {
                        panic!("real Agent rejected jobs-v1 subsystem")
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        let body = serde_json::to_vec(request).unwrap();
        let mut frame = (u32::try_from(body.len()).unwrap()).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        if extra_frame {
            frame.extend_from_within(..);
        }
        channel.data(frame.as_slice()).await.unwrap();
        channel.eof().await.unwrap();
        channel
    }

    pub(super) async fn rpc(&self, client: usize, request: &Value, extra_frame: bool) -> Value {
        let mut channel = self.send(client, request, extra_frame).await;
        let mut frame = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => {
                        frame.extend_from_slice(&data);
                        assert!(frame.len() <= JOB_FRAME_MAX_BYTES + 4);
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("framed jobs-v1 response deadline");
        assert!(frame.len() >= 4);
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        serde_json::from_slice(&frame[4..]).unwrap()
    }

    pub(super) async fn wait_state(&self, client: usize, id: &str, state: Value) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let response = self
                    .rpc(client, &json!({"version":1,"op":"status","id":id}), false)
                    .await;
                assert_eq!(response["ok"], true);
                if response["state"] == state {
                    break;
                }
                assert_eq!(response["state"], json!({"state":"running"}));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual worker reaches expected terminal state");
    }

    pub(super) async fn close(mut self) {
        self.jobs.accepting.store(false, Ordering::Release);
        self.jobs.shutdown.cancel();
        for client in self.clients.drain(..) {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                client.disconnect(Disconnect::ByApplication, "wire fixture complete", "en"),
            )
            .await;
        }
        let _all_job_slots = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(result) = self.sessions.join_next().await {
                result
                    .unwrap()
                    .expect("real SSH session drains after disconnect");
            }
            self.jobs
                .slots
                .clone()
                .acquire_many_owned(MAX_ACTIVE_JOBS as u32)
                .await
                .unwrap()
        })
        .await
        .expect("real sessions and process trees finish before fixture disposal");
        self.jobs.store.clone().close().await;
    }
}

impl Drop for WireFixture {
    fn drop(&mut self) {
        self.jobs.shutdown.cancel();
    }
}

pub(super) async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real process publishes readiness file");
}
