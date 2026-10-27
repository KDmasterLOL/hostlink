//! The executable must not start a second reverse tunnel beside ssh::serve.
#![cfg(unix)]

use hostlink_agent::{AgentConfig, ReverseGateway};
use russh::{
    keys::{Algorithm, PrivateKey, PublicKey, ssh_key::LineEnding},
    server::{self, Auth, Server as _},
};
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct Gateway {
    approved_key: PublicKey,
    reverse_port: u16,
    requests: Arc<AtomicUsize>,
}

impl server::Server for Gateway {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Gateway {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(
            if user == "gateway" && key.key_data() == self.approved_key.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if address != "127.0.0.1" || *port != u32::from(self.reverse_port) {
            return Ok(false);
        }
        // Like the Hub's allocated gateway port, this exact reverse mapping
        // can be owned by only one authenticated Agent session at a time.
        Ok(self.requests.fetch_add(1, Ordering::SeqCst) == 0)
    }
}

fn private_file(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).expect("create owned fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private fixture mode");
}

fn available_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    listener.local_addr().expect("bound port").port()
}

#[tokio::test]
async fn cli_run_starts_only_one_agent_owned_reverse_tunnel() {
    let root = tempfile::tempdir().expect("owned fixture root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private fixture root");

    let mut random = rand::rng();
    let gateway_host = PrivateKey::random(&mut random, Algorithm::Ed25519).unwrap();
    let reverse_identity = PrivateKey::random(&mut random, Algorithm::Ed25519).unwrap();
    let agent_host = PrivateKey::random(&mut random, Algorithm::Ed25519).unwrap();
    let controller = PrivateKey::random(&mut random, Algorithm::Ed25519).unwrap();
    let gateway_identity_file = root.path().join("gateway-identity");
    let gateway_pin_file = root.path().join("gateway.pin");
    let host_file = root.path().join("agent-host");
    let controller_file = root.path().join("authorized_keys");
    private_file(
        &gateway_identity_file,
        reverse_identity.to_openssh(LineEnding::LF).unwrap(),
    );
    private_file(
        &gateway_pin_file,
        gateway_host.public_key().to_openssh().unwrap(),
    );
    private_file(&host_file, agent_host.to_openssh(LineEnding::LF).unwrap());
    private_file(
        &controller_file,
        controller.public_key().to_openssh().unwrap(),
    );
    let jobs = root.path().join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
    hostlink_agent::durable::DurableStore::initialize_fresh(&jobs)
        .await
        .expect("initialize fresh private Agent SQLite fixture")
        .close()
        .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let reverse_port = available_loopback_port();
    let requests = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway {
        approved_key: reverse_identity.public_key().clone(),
        reverse_port,
        requests: requests.clone(),
    };
    let gateway_server = tokio::spawn(async move {
        let config = Arc::new(server::Config {
            keys: vec![gateway_host],
            auth_rejection_time: Duration::ZERO,
            ..Default::default()
        });
        let mut gateway = gateway;
        gateway.run_on_socket(config, &listener).await
    });

    let config = AgentConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], available_loopback_port())),
        user: "agent".into(),
        host_key: host_file,
        authorized_keys: controller_file,
        jobs_root: jobs,
        gateway: Some(ReverseGateway {
            host: "127.0.0.1".into(),
            port: address.port(),
            user: "gateway".into(),
            identity: gateway_identity_file,
            host_public_key: gateway_pin_file,
            remote_port: reverse_port,
        }),
        gateway_alternates: Vec::new(),
    };
    let config_file = root.path().join("agent.json");
    private_file(&config_file, serde_json::to_vec(&config).unwrap());

    let mut agent = tokio::process::Command::new(env!("CARGO_BIN_EXE_hostlink-agent"))
        .arg("run")
        .arg("--config")
        .arg(&config_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start user-owned disposable Agent binary");

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if requests.load(Ordering::SeqCst) > 0 {
                return;
            }
            if let Some(status) = agent.try_wait().expect("poll Agent") {
                panic!("Agent exited before registering its owned reverse tunnel: {status}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if result.is_err() {
        agent.kill().await.expect("stop failed disposable Agent");
    }
    result.expect("Agent registered its single reverse tunnel");

    // A second independent tunnel races with this one and is rejected by the
    // gateway. The public run command must remain alive and register only once.
    tokio::time::sleep(Duration::from_millis(350)).await;
    let observed = requests.load(Ordering::SeqCst);
    let status = agent.try_wait().expect("check Agent process");
    if status.is_none() {
        agent.kill().await.expect("stop disposable Agent");
    }
    gateway_server.abort();
    let _ = gateway_server.await;
    assert_eq!(
        observed, 1,
        "Agent CLI attempted duplicate reverse-port registration"
    );
    assert!(
        status.is_none(),
        "Agent CLI exited unexpectedly after gateway registration"
    );
}
