//! Real Agent -> russh gateway reverse tunnel -> pinned Controller integration.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hostlink::{
    connect::HostConnection,
    hub::{HubConfig as ControllerHubConfig, host_spec_from},
};
use hostlink_agent::{AgentConfig, ReverseGateway, ssh};
use hostlink_hub::{
    EnrollRequest, EnrollResponse, GatewayEndpoint, HubConfig as ServerHubConfig, HubService,
    InviteRequest, InviteResponse, MachineId,
};
use russh::{
    Channel, ChannelOpenFailure,
    keys::{Algorithm, PrivateKey, PublicKey, ssh_key::LineEnding},
    server::{self, Auth, Msg, Server as _},
};
use secrecy::SecretString;
use sha2::Digest as _;
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct Gateway {
    allowed: PublicKey,
    port: u16,
    mappings: Arc<Mutex<HashMap<u16, server::Handle>>>,
    forwards: Arc<AtomicUsize>,
    requested_forwards: Arc<Mutex<Vec<(String, u32)>>>,
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
            if user == "gateway" && key.key_data() == self.allowed.key_data() {
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
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        self.requested_forwards
            .lock()
            .await
            .push((address.to_owned(), *port));
        if address != "127.0.0.1" || *port != u32::from(self.port) {
            return Ok(false);
        }
        let mut mappings = self.mappings.lock().await;
        if mappings.contains_key(&self.port) {
            return Ok(false);
        }
        mappings.insert(self.port, session.handle());
        self.forwards.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        if address == "127.0.0.1" && port == u32::from(self.port) {
            self.mappings.lock().await.remove(&self.port);
        }
        Ok(true)
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if host != "127.0.0.1" || port != u32::from(self.port) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let Some(agent) = self.mappings.lock().await.get(&self.port).cloned() else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        // Do not acknowledge the Controller's channel until the matching
        // Agent-side forwarded channel is confirmed. Propagating an upstream
        // open failure from this callback tears down the entire gateway SSH
        // session, which the nested client reports only as Disconnect.
        let incoming = match tokio::time::timeout(
            Duration::from_secs(10),
            agent.channel_open_forwarded_tcpip("127.0.0.1", u32::from(self.port), "127.0.0.1", 0),
        )
        .await
        {
            Ok(Ok(channel)) => channel,
            Ok(Err(_)) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
            Err(_) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;
        let outgoing = channel.into_stream();
        let incoming = incoming.into_stream();
        tokio::spawn(async move {
            let mut a = outgoing;
            let mut b = incoming;
            let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        });
        Ok(())
    }
}

fn spawn_gateway(
    listener: tokio::net::TcpListener,
    mut gateway: Gateway,
    config: Arc<server::Config>,
) -> tokio::task::JoinHandle<Result<(), std::io::Error>> {
    tokio::spawn(async move { gateway.run_on_socket(config, &listener).await })
}

fn private_file(path: &std::path::Path, key: &PrivateKey) {
    std::fs::write(
        path,
        key.to_openssh(LineEnding::LF)
            .expect("serialize fixture key"),
    )
    .expect("write fixture key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private key mode");
    }
}
fn public_file(path: &std::path::Path, key: &PublicKey) {
    std::fs::write(path, key.to_openssh().expect("serialize public pin"))
        .expect("write public pin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private pin mode");
    }
}

#[tokio::test]
async fn reverse_gateway_runs_pinned_nested_ssh_and_rejects_wrong_pins() {
    let root = tempfile::tempdir().expect("disposable fixture directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private fixture directory");
    }
    let gateway_host =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("gateway host key");
    let gateway_user =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("gateway authorized key");
    let agent_host =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("agent host key");
    let controller =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller key");
    let wrong = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("negative pin");
    let gw_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback gateway");
    let gw_addr = gw_listener.local_addr().expect("gateway address");
    let agent_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback Agent");
    let agent_addr = agent_listener.local_addr().expect("Agent address");
    let reverse_port = {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reverse port");
        let p = socket.local_addr().unwrap().port();
        drop(socket);
        p
    };
    let mappings = Arc::new(Mutex::new(HashMap::new()));
    let forwards = Arc::new(AtomicUsize::new(0));
    let requested_forwards = Arc::new(Mutex::new(Vec::new()));
    let gateway = Gateway {
        allowed: gateway_user.public_key().clone(),
        port: reverse_port,
        mappings: mappings.clone(),
        forwards: forwards.clone(),
        requested_forwards: requested_forwards.clone(),
    };
    let gw_cfg = Arc::new(server::Config {
        keys: vec![gateway_host.clone()],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    let gateway_fixture = gateway.clone();
    let mut gw_task = spawn_gateway(gw_listener, gateway_fixture.clone(), gw_cfg.clone());
    let gw_pin = gateway_host.public_key().clone();
    let gateway_user_file = root.path().join("gateway-user");
    let gateway_pin_file = root.path().join("gateway-pin");
    private_file(&gateway_user_file, &gateway_user);
    public_file(&gateway_pin_file, &gw_pin);
    let agent_host_file = root.path().join("agent-host");
    private_file(&agent_host_file, &agent_host);
    let controller_file = root.path().join("controller");
    private_file(&controller_file, &controller);
    let authorized = root.path().join("authorized");
    std::fs::write(
        &authorized,
        format!("{} test\n", controller.public_key().to_openssh().unwrap()),
    )
    .expect("authorized controller");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600))
            .expect("authorized file mode");
    }
    let jobs = root.path().join("jobs");
    std::fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).expect("jobs mode");
    }
    let agent_config = AgentConfig {
        listen: agent_addr,
        user: "agent".into(),
        host_key: agent_host_file,
        authorized_keys: authorized,
        jobs_root: jobs,
        gateway: Some(ReverseGateway {
            host: "127.0.0.1".into(),
            port: gw_addr.port(),
            user: "gateway".into(),
            identity: gateway_user_file.clone(),
            host_public_key: gateway_pin_file,
            remote_port: reverse_port,
        }),
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serving_config = agent_config.clone();
    let agent_task = tokio::spawn(async move {
        ssh::serve_on(agent_listener, &serving_config, async {
            let _ = shutdown_rx.await;
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while forwards.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reverse forwarding readiness");

    // Exercise the real Hub registry/registration wire contract with the
    // same generated identities and reverse port as the active russh gateway.
    // Hub API calls remain in-process here: the client HTTPS TLS/proxy gates
    // are tested separately by the Hub Client tests.
    let projection = root.path().join("managed-gateway");
    std::fs::create_dir(&projection).expect("managed gateway projection root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&projection, std::fs::Permissions::from_mode(0o700))
            .expect("gateway projection root private");
    }
    let projected_keys = projection.join("hostlink-v2-authorized_keys");
    const OPERATOR_TOKEN: &str = "disposable-hub-operator-token-0123456789abcdef";
    let hub = hostlink_hub::router(
        HubService::new(ServerHubConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 27400)),
            public_url: "https://hub.fixture.test".into(),
            state_root: root.path().join("hostlink-hub-v2"),
            authorized_keys: projected_keys.clone(),
            gateways: vec![GatewayEndpoint {
                host: "127.0.0.1".into(),
                user: "gateway".into(),
                port: gw_addr.port(),
                host_public_key: gw_pin.to_openssh().unwrap(),
            }],
            operator_ssh_public_keys: vec![controller.public_key().to_openssh().unwrap()],
            operator_token: SecretString::from(OPERATOR_TOKEN),
            gateway_lookup_token: SecretString::from(
                "disposable-hub-gateway-lookup-0123456789abcdef",
            ),
            port_from: reverse_port,
            port_to: reverse_port,
            reserved_ports: BTreeSet::new(),
        })
        .expect("isolated managed Hub"),
    );
    let invite_response = hub
        .clone()
        .oneshot(
            Request::post("/v2/invites")
                .header("authorization", format!("Bearer {OPERATOR_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&InviteRequest {
                        ttl_seconds: 900,
                        name: Some("managed-agent".into()),
                        rotate_machine_id: None,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("Hub v2 invite HTTP");
    assert_eq!(invite_response.status(), StatusCode::CREATED);
    let invite: InviteResponse = serde_json::from_slice(
        &to_bytes(invite_response.into_body(), 64 * 1024)
            .await
            .expect("invite body"),
    )
    .expect("typed one-use invite");
    let enroll_response = hub
        .clone()
        .oneshot(
            Request::post("/v2/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&EnrollRequest {
                        token: invite.token.clone(),
                        machine_id: MachineId::parse("managed-agent-id").unwrap(),
                        name: "managed-agent".into(),
                        hostname: "managed-fixture".into(),
                        os: "linux".into(),
                        arch: "x86_64".into(),
                        agent_version: "0.1.0".into(),
                        ssh_public_key: gateway_user.public_key().to_openssh().unwrap(),
                        ssh_host_public_key: agent_host.public_key().to_openssh().unwrap(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("Hub v2 enrollment HTTP");
    assert_eq!(enroll_response.status(), StatusCode::CREATED);
    let enrolled: EnrollResponse = serde_json::from_slice(
        &to_bytes(enroll_response.into_body(), 64 * 1024)
            .await
            .expect("enrollment body"),
    )
    .expect("typed registered host");
    assert_eq!(enrolled.host.remote_port, reverse_port);
    assert!(
        std::fs::read_to_string(&projected_keys)
            .expect("approved reverse key projection")
            .contains("hostlink-agent:managed-agent-id")
    );
    let spec = host_spec_from(
        enrolled.host.clone(),
        &enrolled.gateways[0],
        &ControllerHubConfig {
            hub_url: "https://hub.fixture.test".into(),
            token_file: root.path().join("no-network-token"),
            ssh_user: "agent".into(),
            identity: controller_file.clone(),
            gateway_identity: gateway_user_file.clone(),
        },
    )
    .await
    .expect("build pinned HostSpec from actual Hub-issued identity/route");
    assert_eq!(spec.gateway.as_ref().unwrap().address, gw_addr);
    assert_eq!(spec.host_public_key, enrolled.host.ssh_host_public_key);
    let mut host = tokio::time::timeout(Duration::from_secs(15), HostConnection::connect(&spec))
        .await
        .expect("nested SSH deadline")
        .expect("strictly pinned nested connection");
    let result = host
        .exec("printf 'gw\\000\\377'; exit 7", &[])
        .await
        .expect("exec through gateway");
    assert_eq!(result.stdout, b"gw\0\xff");
    assert_eq!(result.exit_code, 7);
    let artifact = b"gateway-sftp\0\xff";
    let artifact_name = format!("{:x}.upload", sha2::Sha256::digest(artifact));
    host.sftp_upload(&artifact_name, artifact)
        .await
        .expect("SFTP upload through nested SSH transport");
    assert_eq!(
        host.sftp_download(&artifact_name)
            .await
            .expect("SFTP download through nested SSH transport"),
        artifact
    );
    host.close().await.expect("close nested sessions");
    // A consumed invite cannot overwrite the registered public SSH host key.
    let replay = hub
        .clone()
        .oneshot(
            Request::post("/v2/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&EnrollRequest {
                        token: invite.token,
                        machine_id: MachineId::parse("managed-agent-id").unwrap(),
                        name: "managed-agent".into(),
                        hostname: "managed-fixture".into(),
                        os: "linux".into(),
                        arch: "x86_64".into(),
                        agent_version: "0.1.0".into(),
                        ssh_public_key: gateway_user.public_key().to_openssh().unwrap(),
                        ssh_host_public_key: wrong.public_key().to_openssh().unwrap(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .expect("Hub v2 replay HTTP");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    // Exercise the Agent's outbound authentication and mapping checks against the
    // live russh gateway while the first reverse mapping is still owned.
    let mut wrong_agent_pin = agent_config.clone();
    let wrong_pin_path = root.path().join("wrong-gateway-pin");
    public_file(&wrong_pin_path, wrong.public_key());
    wrong_agent_pin.gateway.as_mut().unwrap().host_public_key = wrong_pin_path;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            hostlink_agent::tunnel::run(&wrong_agent_pin, std::future::pending::<()>()),
        )
        .await
        .expect("wrong Agent gateway pin deadline")
        .is_err(),
        "Agent rejects an unpinned gateway key"
    );
    let mut wrong_agent_user = agent_config.clone();
    wrong_agent_user.gateway.as_mut().unwrap().user = "unauthorized".into();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            hostlink_agent::tunnel::run(&wrong_agent_user, std::future::pending::<()>()),
        )
        .await
        .expect("wrong Agent gateway user deadline")
        .is_err(),
        "gateway rejects an unauthorized Agent identity"
    );
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            hostlink_agent::tunnel::run(&agent_config, std::future::pending::<()>()),
        )
        .await
        .expect("duplicate mapping deadline")
        .is_err(),
        "gateway refuses a second owner for the same reverse port"
    );
    assert!(
        requested_forwards
            .lock()
            .await
            .iter()
            .all(|(address, port)| address == "127.0.0.1" && *port == u32::from(reverse_port)),
        "Agent only requests the exact loopback mapping; no public bind is attempted"
    );

    let mut wrong_gateway = spec.clone();
    wrong_gateway.gateway.as_mut().unwrap().user = "unauthorized".into();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            HostConnection::connect(&wrong_gateway)
        )
        .await
        .unwrap()
        .is_err(),
        "gateway rejects an unauthorized user"
    );
    let mut unavailable_gateway = spec.clone();
    unavailable_gateway
        .gateway
        .as_mut()
        .unwrap()
        .host_public_key = wrong.public_key().to_openssh().unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            HostConnection::connect(&unavailable_gateway)
        )
        .await
        .unwrap()
        .is_err(),
        "reachable target does not become a direct fallback when gateway authentication fails"
    );
    let mut wrong_target = spec;
    wrong_target.host_public_key = wrong.public_key().to_openssh().unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(10),
            HostConnection::connect(&wrong_target)
        )
        .await
        .unwrap()
        .is_err(),
        "target pin mismatch fails closed without direct fallback"
    );

    // Drop and restart only the disposable SSH gateway. The Agent's existing
    // backoff loop must reauthenticate and reclaim the same loopback mapping.
    // Aborting the accept loop does not close russh's independently spawned
    // sessions. Explicitly disconnect the Agent's active gateway connection,
    // otherwise this fixture never exercises the reconnect path.
    let live_agents: Vec<_> = mappings.lock().await.values().cloned().collect();
    for agent in live_agents {
        agent
            .disconnect(
                russh::Disconnect::ByApplication,
                "disposable gateway restart".into(),
                String::new(),
            )
            .await
            .expect("disconnect Agent from disposable gateway");
    }
    gw_task.abort();
    let _ = gw_task.await;
    mappings.lock().await.clear();
    let restarted_listener = tokio::net::TcpListener::bind(gw_addr)
        .await
        .expect("restart gateway on its owned ephemeral endpoint");
    gw_task = spawn_gateway(restarted_listener, gateway_fixture, gw_cfg);
    let reconnect = tokio::time::timeout(Duration::from_secs(10), async {
        while forwards.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if reconnect.is_err() {
        if agent_task.is_finished() {
            panic!("Agent completed prematurely: {:?}", agent_task.await);
        }
        panic!(
            "Agent gateway reconnect readiness: forwards={} map_count={:?} requests={:?}",
            forwards.load(Ordering::SeqCst),
            mappings.try_lock().map(|v| v.len()),
            requested_forwards.try_lock().map(|v| v.clone())
        );
    }
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(7), agent_task)
        .await
        .expect("Agent fixture shutdown deadline")
        .expect("Agent fixture task join")
        .expect("Agent fixture shutdown result");
    gw_task.abort();
}
