//! Disposable real-russh coverage for explicit Agent gateway failover.
use hostlink_agent::{AgentConfig, ReverseGateway, ssh};
use russh::{
    Channel, ChannelOpenFailure, client,
    keys::{Algorithm, PrivateKey, PublicKey, PublicKeyOrCertificate, ssh_key::LineEnding},
    server::{self, Auth, Msg, Server as _},
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Gateway {
    agent_key: PublicKey,
    controller_key: PublicKey,
    port: u16,
    mappings: Arc<Mutex<HashMap<u16, server::Handle>>>,
    forwards: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<(String, u32)>>>,
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
            if user == "gateway"
                && (key.key_data() == self.agent_key.key_data()
                    || key.key_data() == self.controller_key.key_data())
            {
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
        self.requests.lock().await.push((address.to_owned(), *port));
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
        _: &mut server::Session,
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
        let incoming = match agent
            .channel_open_forwarded_tcpip("127.0.0.1", u32::from(self.port), "127.0.0.1", 0)
            .await
        {
            Ok(channel) => channel,
            Err(_) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut a = channel.into_stream();
            let mut b = incoming.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        });
        Ok(())
    }
}

struct AgentPin(PublicKey);

impl client::Handler for AgentPin {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(presented.certificate().is_none()
            && presented.public_key().algorithm() == Algorithm::Ed25519
            && presented.public_key().key_data() == self.0.key_data())
    }
}

fn write_private(path: &Path, key: &PrivateKey) {
    std::fs::write(
        path,
        key.to_openssh(LineEnding::LF)
            .expect("serialize private fixture key"),
    )
    .expect("write private fixture key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private fixture permissions");
    }
    #[cfg(windows)]
    protect_windows_fixture(path, false);
}

fn write_pin(path: &Path, key: &PublicKey) {
    std::fs::write(path, key.to_openssh().expect("serialize host pin")).expect("write host pin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private fixture permissions");
    }
    #[cfg(windows)]
    protect_windows_fixture(path, false);
}

#[cfg(windows)]
fn protect_windows_fixture(path: &Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let owner = windows_permissions::utilities::current_process_sid().expect("current SID");
    let sid = ConvertSidToStringSid(&owner).expect("format SID");
    let _ = directory;
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{})", sid.to_string_lossy())
            .parse()
            .expect("construct private ACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(owner.as_ref()),
        None,
        descriptor.dacl(),
        None,
    )
    .expect("protect disposable Agent test fixture");
}

fn unused_loopback_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    socket.local_addr().expect("reserved port").port()
}

fn route(port: u16, identity: &Path, pin: &Path, remote_port: u16) -> ReverseGateway {
    ReverseGateway {
        host: "127.0.0.1".into(),
        port,
        user: "gateway".into(),
        identity: identity.to_path_buf(),
        host_public_key: pin.to_path_buf(),
        remote_port,
    }
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("fixture root");
    #[cfg(windows)]
    protect_windows_fixture(root.path(), true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
    }
    root
}

fn launch_gateway(
    listener: tokio::net::TcpListener,
    host_key: PrivateKey,
    gateway: Gateway,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            ..Default::default()
        });
        let mut server = gateway;
        server.run_on_socket(config, &listener).await
    })
}

#[tokio::test]
async fn unavailable_primary_fails_over_to_pinned_route_and_controller_reaches_agent() {
    let root = private_root();
    let agent_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let agent_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let first_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let second_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let identity = root.path().join("gateway_identity");
    let first_pin = root.path().join("first.pub");
    let second_pin = root.path().join("second.pub");
    let agent_host_path = root.path().join("agent_host");
    let authorized = root.path().join("authorized_keys");
    let jobs = root.path().join("jobs");
    write_private(&identity, &agent_key);
    write_pin(&first_pin, first_host.public_key());
    write_pin(&second_pin, second_host.public_key());
    write_private(&agent_host_path, &agent_host);
    std::fs::write(
        &authorized,
        format!("{}\n", controller.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    #[cfg(windows)]
    protect_windows_fixture(&authorized, false);
    std::fs::create_dir(&jobs).unwrap();
    #[cfg(windows)]
    protect_windows_fixture(&jobs, true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600))
            .expect("authorized Controller keys must be private");
        std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700))
            .expect("Agent job store must be private");
    }
    hostlink_agent::jobs::JobStore::initialize_fresh(&jobs)
        .await
        .expect("initialize fresh private Agent SQLite fixture")
        .close()
        .await;

    let reverse_port = unused_loopback_port();
    let unavailable = unused_loopback_port();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let mappings = Arc::new(Mutex::new(HashMap::new()));
    let forwards = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let gateway = Gateway {
        agent_key: agent_key.public_key().clone(),
        controller_key: controller.public_key().clone(),
        port: reverse_port,
        mappings,
        forwards: forwards.clone(),
        requests: requests.clone(),
    };
    let gateway_for_restart = gateway.clone();
    let gateway_task = launch_gateway(listener, second_host.clone(), gateway);
    let agent_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_addr = agent_listener.local_addr().unwrap();
    let config = AgentConfig {
        listen: agent_addr,
        user: "agent".into(),
        host_key: agent_host_path,
        authorized_keys: authorized,
        jobs_root: jobs,
        board_listen: None,
        gateway: Some(route(unavailable, &identity, &first_pin, reverse_port)),
        gateway_alternates: vec![route(
            gateway_addr.port(),
            &identity,
            &second_pin,
            reverse_port,
        )],
    };
    let (agent_stop, agent_shutdown) = tokio::sync::oneshot::channel();
    let config_for_server = config.clone();
    let agent_server = tokio::spawn(async move {
        ssh::serve_on(agent_listener, &config_for_server, async {
            let _ = agent_shutdown.await;
        })
        .await
    });
    // serve_on already owns the reverse tunnel for a gateway-configured Agent;
    // spawning another tunnel would compete for the exact same reverse port.
    tokio::time::timeout(Duration::from_secs(8), async {
        while forwards.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approved alternate reverse route became ready");

    // Connect the Controller over the active edge and verify the nested Agent
    // SSH host pin and authorized Controller key against the actual Agent.
    let gateway_session = client::connect(
        Arc::new(client::Config::default()),
        gateway_addr,
        AgentPin(second_host.public_key().clone()),
    )
    .await
    .expect("pin second gateway");
    let mut gateway_session = gateway_session;
    assert!(
        gateway_session
            .authenticate_publickey(
                "gateway",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(controller.clone()), None),
            )
            .await
            .unwrap()
            .success()
    );
    let channel = gateway_session
        .channel_open_direct_tcpip("127.0.0.1", u32::from(reverse_port), "127.0.0.1", 0)
        .await
        .expect("open exact reverse port through gateway");
    let mut target = client::connect_stream(
        Arc::new(client::Config::default()),
        channel.into_stream(),
        AgentPin(agent_host.public_key().clone()),
    )
    .await
    .expect("pin nested Agent host key");
    assert!(
        target
            .authenticate_publickey(
                "agent",
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(controller), None),
            )
            .await
            .unwrap()
            .success()
    );
    let seen = requests.lock().await;
    assert!(!seen.is_empty(), "Agent never requested reverse forwarding");
    assert!(
        seen.iter()
            .all(|(address, port)| address == "127.0.0.1" && *port == u32::from(reverse_port)),
        "all gateway retries must request only the exact approved loopback port"
    );
    drop(seen);

    // Drop the active edge and bring the same pinned gateway back on the same
    // address. The Agent must clean up its old mapping and establish a fresh
    // reverse forward without requiring a process restart.
    drop(target);
    drop(gateway_session);
    assert!(
        !agent_server.is_finished(),
        "the Agent and its owned reverse tunnel must still be running"
    );
    let before_restart = forwards.load(Ordering::SeqCst);
    // Stopping the listener alone leaves russh's accepted sessions running.
    // Close the old Agent-side SSH session to exercise *actual* reconnection.
    let live_agents: Vec<_> = gateway_for_restart
        .mappings
        .lock()
        .await
        .values()
        .cloned()
        .collect();
    for agent in live_agents {
        agent
            .disconnect(
                russh::Disconnect::ByApplication,
                "disposable gateway restart".into(),
                String::new(),
            )
            .await
            .expect("disconnect only the disposable Agent session");
    }
    gateway_task.abort();
    let _ = gateway_task.await;
    gateway_for_restart.mappings.lock().await.clear();
    let restarted_listener = tokio::net::TcpListener::bind(gateway_addr)
        .await
        .expect("restart the disposable gateway on its original address");
    let restarted_gateway =
        launch_gateway(restarted_listener, second_host.clone(), gateway_for_restart);
    tokio::time::timeout(Duration::from_secs(15), async {
        while forwards.load(Ordering::SeqCst) <= before_restart {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Agent re-established the approved reverse mapping after gateway restart");

    let _ = agent_stop.send(());
    agent_server.await.unwrap().unwrap();
    restarted_gateway.abort();
    let _ = restarted_gateway.await;
}

#[tokio::test]
async fn bad_primary_pin_fails_without_trying_healthy_alternate() {
    let root = private_root();
    let identity_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let gateway_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let wrong_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let pin_path = root.path().join("wrong.pub");
    let correct_pin_path = root.path().join("correct.pub");
    let correct_pin_path_alternate = root.path().join("correct-alternate.pub");
    let identity_path = root.path().join("identity");
    write_private(&identity_path, &identity_key);
    write_pin(&pin_path, wrong_host.public_key());
    write_pin(&correct_pin_path, gateway_host.public_key());
    write_pin(&correct_pin_path_alternate, gateway_host.public_key());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let forwards = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway {
        agent_key: identity_key.public_key().clone(),
        controller_key: identity_key.public_key().clone(),
        port: 40222,
        mappings: Arc::new(Mutex::new(HashMap::new())),
        forwards: forwards.clone(),
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let gateway_task = launch_gateway(listener, gateway_host, gateway);
    let config = AgentConfig {
        listen: "127.0.0.1:40223".parse().unwrap(),
        user: "agent".into(),
        host_key: root.path().join("unused-host"),
        authorized_keys: root.path().join("unused-authorized"),
        jobs_root: root.path().join("unused-jobs"),
        board_listen: None,
        gateway: Some(route(address.port(), &identity_path, &pin_path, 40222)),
        gateway_alternates: vec![route(
            address.port().saturating_add(1),
            &identity_path,
            &correct_pin_path,
            40222,
        )],
    };
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        hostlink_agent::tunnel::run(&config, std::future::pending::<()>()),
    )
    .await
    .expect("permanent pin mismatch returns promptly")
    .expect_err("wrong pin must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(forwards.load(Ordering::SeqCst), 0);

    let unauthorized_identity = root.path().join("unauthorized-identity");
    write_private(
        &unauthorized_identity,
        &PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
    );
    let wrong_key = AgentConfig {
        listen: "127.0.0.1:40223".parse().unwrap(),
        user: "agent".into(),
        host_key: root.path().join("unused-host"),
        authorized_keys: root.path().join("unused-authorized"),
        jobs_root: root.path().join("unused-jobs"),
        board_listen: None,
        gateway: Some(route(
            address.port(),
            &unauthorized_identity,
            &correct_pin_path,
            40222,
        )),
        gateway_alternates: vec![route(
            address.port().saturating_add(1),
            &unauthorized_identity,
            &correct_pin_path_alternate,
            40222,
        )],
    };
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        hostlink_agent::tunnel::run(&wrong_key, std::future::pending::<()>()),
    )
    .await
    .expect("rejected reverse identity returns promptly")
    .expect_err("unauthorized Agent key must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(forwards.load(Ordering::SeqCst), 0);

    let mut wrong_user = AgentConfig {
        listen: "127.0.0.1:40223".parse().unwrap(),
        user: "agent".into(),
        host_key: root.path().join("unused-host"),
        authorized_keys: root.path().join("unused-authorized"),
        jobs_root: root.path().join("unused-jobs"),
        board_listen: None,
        gateway: Some(route(
            address.port(),
            &identity_path,
            &correct_pin_path,
            40222,
        )),
        gateway_alternates: vec![route(
            address.port(),
            &identity_path,
            &correct_pin_path_alternate,
            40222,
        )],
    };
    wrong_user.gateway.as_mut().unwrap().user = "unauthorized".into();
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        hostlink_agent::tunnel::run(&wrong_user, std::future::pending::<()>()),
    )
    .await
    .expect("authorization denial returns promptly")
    .expect_err("wrong gateway user must fail closed");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(forwards.load(Ordering::SeqCst), 0);
    gateway_task.abort();
}

#[test]
fn config_rejects_conflicting_routes_and_port_and_key_paths() {
    let mut config = AgentConfig {
        listen: "127.0.0.1:40223".parse().unwrap(),
        user: "agent".into(),
        host_key: PathBuf::from("host"),
        authorized_keys: PathBuf::from("authorized"),
        jobs_root: PathBuf::from("jobs"),
        board_listen: None,
        gateway: Some(route(
            2200,
            Path::new("identity"),
            Path::new("pin-a"),
            40222,
        )),
        gateway_alternates: vec![route(
            2200,
            Path::new("identity"),
            Path::new("pin-b"),
            40222,
        )],
    };
    assert!(config.validate().is_err(), "duplicate edge identity");
    config.gateway_alternates[0].port = 2201;
    config.gateway_alternates[0].remote_port = 40224;
    assert!(config.validate().is_err(), "conflicting assigned port");
    config.gateway_alternates[0].remote_port = 40222;
    config.gateway_alternates[0].host_public_key = PathBuf::from("identity");
    assert!(
        config.validate().is_err(),
        "identity cannot alias a host pin"
    );
}
