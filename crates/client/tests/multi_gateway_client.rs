//! Real pinned client failover through disposable loopback russh gateways.

use hostlink::{GatewayHop, GatewayRoute, HostSpec, connect::HostConnection, hub::HubConfig};
use hostlink_agent::{AgentConfig, ssh};
use russh::{
    Channel, ChannelOpenFailure,
    keys::{Algorithm, PrivateKey, PublicKey, ssh_key::LineEnding},
    server::{self, Auth, Msg, Server as _},
};
use sha2::Digest as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone)]
struct Gateway {
    allowed: PublicKey,
    port: u16,
    target: SocketAddr,
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
        match tokio::net::TcpStream::connect(self.target).await {
            Ok(target) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut a = channel.into_stream();
                    let mut b = target;
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                });
            }
            Err(_) => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }
}

fn private_file(path: &std::path::Path, key: &PrivateKey) {
    std::fs::write(path, key.to_openssh(LineEnding::LF).unwrap()).unwrap();
    protect_fixture_path(path, false);
}

fn protect_fixture_path(path: &std::path::Path, directory: bool) {
    #[cfg(unix)]
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
    .expect("protect current-user fixture");
    #[cfg(windows)]
    {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
        use windows_permissions::{LocalBox, SecurityDescriptor};

        let owner = windows_permissions::utilities::current_process_sid().expect("current SID");
        let sid = ConvertSidToStringSid(&owner).expect("format owner SID");
        let inheritance = if directory { "OICI" } else { "" };
        let descriptor: LocalBox<SecurityDescriptor> =
            format!("D:P(A;{inheritance};FA;;;{})", sid.to_string_lossy())
                .parse()
                .expect("owner-only fixture DACL");
        SetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner
                | SecurityInformation::Dacl
                | SecurityInformation::ProtectedDacl,
            Some(owner.as_ref()),
            None,
            descriptor.dacl(),
            None,
        )
        .expect("protect current-user gateway fixture");
    }
}

#[test]
fn legacy_manual_host_and_hub_config_without_route_preference_still_parse() {
    let manual = r#"{
        "endpoint":"127.0.0.1:2222","user":"agent","identity":"agent.key",
        "host_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
        "gateway":{"address":"127.0.0.1:2200","user":"gateway","identity":"gateway.key",
        "host_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake","reverse_port":23001}
    }"#;
    let spec: HostSpec = serde_json::from_str(manual).expect("legacy one-gateway HostSpec parses");
    assert!(spec.gateway.unwrap().alternates.is_empty());
    let config: HubConfig = serde_json::from_str(
        r#"{
        "hub_url":"https://hub.example","token_file":"token","ssh_user":"agent",
        "identity":"agent.key","gateway_identity":"gateway.key"
    }"#,
    )
    .expect("legacy controller config parses");
    assert!(config.preferred_gateway.is_none());
}
async fn gateway(
    target: SocketAddr,
    user_key: PublicKey,
    port: u16,
) -> (SocketAddr, String, tokio::task::JoinHandle<()>) {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let pin = key.public_key().to_openssh().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    let mut handler = Gateway {
        allowed: user_key,
        port,
        target,
    };
    let task = tokio::spawn(async move {
        handler.run_on_socket(config, &listener).await.unwrap();
    });
    (address, pin, task)
}

#[tokio::test]
async fn unavailable_primary_fails_over_and_pinned_nested_agent_execs_and_sftp() {
    let root = tempfile::tempdir().unwrap();
    protect_fixture_path(root.path(), true);
    let controller = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let gateway_user = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let agent_host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller_path = root.path().join("controller");
    private_file(&controller_path, &controller);
    let gateway_path = root.path().join("gateway-user");
    private_file(&gateway_path, &gateway_user);
    let agent_path = root.path().join("agent-host");
    private_file(&agent_path, &agent_host);
    let authorized = root.path().join("authorized");
    std::fs::write(
        &authorized,
        format!(
            "{} fixture\n",
            controller.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    protect_fixture_path(&authorized, false);
    let jobs = root.path().join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    protect_fixture_path(&jobs, true);
    hostlink_agent::durable::DurableStore::initialize_fresh(&jobs)
        .await
        .expect("private Agent fixture SQLite store")
        .close()
        .await;
    let agent_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_address = agent_listener.local_addr().unwrap();
    let reverse_port = 43127;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let agent_config = AgentConfig {
        listen: agent_address,
        user: "agent".into(),
        host_key: agent_path,
        authorized_keys: authorized,
        jobs_root: jobs,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let config = agent_config.clone();
    let agent_task = tokio::spawn(async move {
        ssh::serve_on(agent_listener, &config, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    let (active_addr, active_pin, active_task) = gateway(
        agent_address,
        gateway_user.public_key().clone(),
        reverse_port,
    )
    .await;
    let (second_addr, second_pin, second_task) = gateway(
        agent_address,
        gateway_user.public_key().clone(),
        reverse_port,
    )
    .await;
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    let dead_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let wrong_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let route = |address, pin: String, user: &str| GatewayRoute {
        address,
        user: user.into(),
        identity: gateway_path.clone(),
        host_public_key: pin,
    };
    let spec = HostSpec {
        endpoint: SocketAddr::from(([127, 0, 0, 1], agent_address.port())),
        user: "agent".into(),
        identity: controller_path,
        host_public_key: agent_host.public_key().to_openssh().unwrap(),
        gateway: Some(GatewayHop {
            address: dead_addr,
            user: "gateway".into(),
            identity: gateway_path.clone(),
            host_public_key: dead_key.public_key().to_openssh().unwrap(),
            reverse_port,
            alternates: vec![
                route(active_addr, active_pin.clone(), "gateway"),
                route(second_addr, second_pin.clone(), "gateway"),
            ],
        }),
    };
    let mut host = HostConnection::connect(&spec)
        .await
        .expect("transient refused primary advances to approved route");
    let result = host
        .exec("printf 'multi\\000\\377'; exit 7", &[])
        .await
        .unwrap();
    assert_eq!(result.stdout, b"multi\0\xff");
    assert_eq!(result.exit_code, 7);
    let data = b"multi-gateway-sftp\0\xff";
    let name = format!("{:x}.upload", sha2::Sha256::digest(data));
    host.sftp_upload(&name, data).await.unwrap();
    assert_eq!(host.sftp_download(&name).await.unwrap(), data);
    host.close().await.unwrap();

    // A healthy alternate is never consulted after the selected gateway presents the wrong key.
    let mut wrong_pin = spec.clone();
    let gateway = wrong_pin.gateway.as_mut().unwrap();
    gateway.address = active_addr;
    gateway.host_public_key = wrong_key.public_key().to_openssh().unwrap();
    gateway.alternates = vec![route(second_addr, second_pin.clone(), "gateway")];
    assert!(HostConnection::connect(&wrong_pin).await.is_err());

    // Route user ownership is part of the approved record and cannot be silently corrected.
    let mut wrong_owner = spec.clone();
    wrong_owner.gateway.as_mut().unwrap().address = active_addr;
    wrong_owner.gateway.as_mut().unwrap().alternates =
        vec![route(second_addr, second_pin, "gateway")];
    // A user mismatch is rejected by the gateway, and auth denial is not a failover signal.
    wrong_owner.gateway.as_mut().unwrap().user = "other-owner".into();
    assert!(HostConnection::connect(&wrong_owner).await.is_err());
    assert_eq!(spec.gateway.as_ref().unwrap().reverse_port, reverse_port);
    let _ = shutdown_tx.send(());
    agent_task.abort();
    active_task.abort();
    second_task.abort();
}
