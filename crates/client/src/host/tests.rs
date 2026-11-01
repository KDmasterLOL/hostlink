//! Domain regressions plus a disposable Hub → HTTPS → pinned russh fixture.
//! Kept together so the fixture and its cross-layer scenarios have one owner.

use super::*;
use secrecy::{ExposeSecret, SecretString};

#[test]
fn pending_invitation_has_only_requested_identity_and_redacts_its_token() {
    let token = "a".repeat(64);
    let expires_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 900;
    for name in [None, Some("requested-host".to_owned())] {
        let pending = PendingHost::from_invitation(
            name.clone(),
            InviteResponse {
                token: SecretString::from(token.clone()),
                expires_at,
            },
        )
        .unwrap();
        assert_eq!(pending.requested_name(), name.as_deref());
        assert!(!format!("{pending:?}").contains(&token));
        let invitation = pending.into_invitation();
        assert_eq!(invitation.expires_at, expires_at);
        assert_eq!(invitation.token.expose_secret(), &token);
    }
}

#[test]
fn pending_rejects_past_and_current_utc_expiry_without_exposing_token() {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = "b".repeat(64);
    for expires_at in [i64::MIN, -1, 0, now - 60, now] {
        let error = PendingHost::from_invitation(
            None,
            InviteResponse {
                token: SecretString::from(token.clone()),
                expires_at,
            },
        )
        .unwrap_err();
        assert!(matches!(error, HostError::ExpiredInvitation));
        assert!(!format!("{error} {error:?}").contains(&token));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn host_errors_preserve_the_existing_hub_and_ssh_error_owners() {
    let hub: HostError = HubClientError::Unauthorized.into();
    assert!(matches!(hub, HostError::Hub(HubClientError::Unauthorized)));
    assert!(
        std::error::Error::source(&hub)
            .unwrap()
            .is::<HubClientError>()
    );
    let ssh: HostError = SshClientError::Timeout.into();
    assert!(matches!(ssh, HostError::Ssh(SshClientError::Timeout)));
    assert!(
        std::error::Error::source(&ssh)
            .unwrap()
            .is::<SshClientError>()
    );
}

// Reuse the existing process/certificate helpers rather than adding a TLS stack
// or a test-only public HTTP constructor to the production Hub client.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "fixture.rs"]
mod fixture;
#[cfg(target_os = "linux")]
use {
    fixture::{Children, key, private_dir, private_key_file, private_write, public_key},
    russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding},
    std::{
        fs,
        net::{SocketAddr, TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::Instant,
    },
};

#[cfg(target_os = "linux")]
mod managed {
    use super::*;
    use axum::{Router, body::Body, http::Request};
    use hostlink_hub::{
        EnrollRequest, EnrollResponse, GatewayEndpoint, HubConfig as ServerConfig, HubService,
        RegisteredHost, router,
    };
    use russh::{
        Channel, ChannelOpenFailure,
        keys::PublicKey,
        server::{self, Auth, Msg, Server as _},
    };
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };
    use tower::ServiceExt;

    const OPERATOR: &str = "operator-domain-test-token-0123456789";
    const EDGE: &str = "edge-domain-test-token-01234567890123";

    struct Task(tokio::task::JoinHandle<()>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    struct HubFixture {
        hub: HubClient,
        config: HubConfig,
        app: Router,
        requests: Arc<Mutex<Vec<String>>>,
        _server: Task,
        _children: Children,
        _root: tempfile::TempDir,
    }

    impl HubFixture {
        async fn start(gateway: GatewayEndpoint, controller: &PrivateKey) -> Self {
            let root = tempfile::tempdir().unwrap();
            private_dir(&root.path().join("gateway"));
            let service = HubService::new(ServerConfig {
                listen: "127.0.0.1:1".parse().unwrap(),
                public_url: "https://hub.fixture".into(),
                state_root: root.path().join("hostlink-hub-v2"),
                authorized_keys: root.path().join("gateway/hostlink-v2-authorized_keys"),
                gateways: vec![gateway],
                operator_ssh_public_keys: vec![public_key(controller)],
                operator_token: OPERATOR.into(),
                gateway_lookup_token: EDGE.into(),
                port_from: 41000,
                port_to: 41010,
                reserved_ports: BTreeSet::new(),
            })
            .unwrap();
            let app = router(service);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let observed = requests.clone();
            let served = app.clone().layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    observed.lock().unwrap().push(format!(
                        "{} {}",
                        request.method(),
                        request.uri().path()
                    ));
                    async move { next.run(request).await }
                },
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = Task(tokio::spawn(async move {
                axum::serve(listener, served).await.unwrap();
            }));

            let (ca, cert, tls_key) = fixture::write_server_certificate(root.path());
            let port = fixture::free_port();
            let caddyfile = root.path().join("Caddyfile");
            private_write(
                &caddyfile,
                format!(
                    "{{\n admin off\n auto_https off\n persist_config off\n}}\nhttps://localhost:{port} {{\n bind 127.0.0.1\n tls {} {}\n reverse_proxy http://{address}\n}}\n",
                    cert.display(),
                    tls_key.display(),
                ),
            );
            let mut children = Children {
                children: Vec::new(),
                stopped: false,
            };
            let mut command = Command::new(
                std::env::var_os("HOSTLINK_CADDY_BIN").unwrap_or_else(|| "/usr/bin/caddy".into()),
            );
            command
                .args(["run", "--config"])
                .arg(&caddyfile)
                .args(["--adapter", "caddyfile"])
                .env("XDG_CONFIG_HOME", root.path().join("caddy-config"))
                .env("XDG_DATA_HOME", root.path().join("caddy-data"))
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            fixture::wait_port(([127, 0, 0, 1], port).into(), Some(children.start(command)));
            let config = HubConfig {
                hub_url: format!("https://localhost:{port}"),
                hub_ca_cert: Some(ca),
                token_file: root.path().join("operator.token"),
                ssh_user: "agent".into(),
                identity: root.path().join("controller"),
                gateway_identity: root.path().join("controller"),
                preferred_gateway: None,
            };
            private_write(&config.token_file, OPERATOR);
            private_key_file(&config.identity, controller);
            let hub = HubClient::from_config(&config).unwrap();
            Self {
                hub,
                config,
                app,
                requests,
                _server: server,
                _children: children,
                _root: root,
            }
        }

        fn take_requests(&self) -> Vec<String> {
            std::mem::take(&mut *self.requests.lock().unwrap())
        }

        async fn enroll(&self, id: &str, name: &str, target_pin: String) -> RegisteredHost {
            let pending = Host::create(&self.hub, Some(name.into()), 900)
                .await
                .unwrap();
            assert_eq!(pending.requested_name(), Some(name));
            let request = EnrollRequest {
                token: pending.into_invitation().token,
                machine_id: MachineId::parse(id).unwrap(),
                name: name.into(),
                hostname: "fixture".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                agent_version: "0.1.0".into(),
                ssh_public_key: public_key(&key()),
                ssh_host_public_key: target_pin,
            };
            let response = self
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v2/enroll")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&request).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response.status().is_success());
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<EnrollResponse>(&bytes)
                .unwrap()
                .host
        }
    }

    // Real authenticated russh servers; the gateway forwards only its approved
    // loopback reverse port, as in the existing multi_gateway_client fixture.
    #[derive(Clone)]
    struct SshFixture {
        allowed: PublicKey,
        target: Option<SocketAddr>,
    }
    impl server::Server for SshFixture {
        type Handler = Self;
        fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
            self.clone()
        }
    }
    impl server::Handler for SshFixture {
        type Error = russh::Error;
        async fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
            Ok(
                if matches!(user, "agent" | "gateway") && key.key_data() == self.allowed.key_data()
                {
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
            // The Hub derives a distinct reverse port from each machine ID.
            // Accept its configured disposable range, not one hardcoded ID's port.
            if let Some(target) = self.target
                && host == "127.0.0.1"
                && (41000..=41010).contains(&port)
            {
                let mut stream = tokio::net::TcpStream::connect(target).await?;
                reply.accept().await;
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut channel.into_stream(), &mut stream)
                        .await;
                });
            } else {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
            Ok(())
        }
    }

    async fn ssh(controller: &PrivateKey, target: Option<SocketAddr>) -> (GatewayEndpoint, Task) {
        let host_key = key();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = GatewayEndpoint {
            host: "127.0.0.1".into(),
            user: "gateway".into(),
            port: listener.local_addr().unwrap().port(),
            host_public_key: public_key(&host_key),
        };
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            ..Default::default()
        });
        let mut handler = SshFixture {
            allowed: controller.public_key().clone(),
            target,
        };
        let task = Task(tokio::spawn(async move {
            handler.run_on_socket(config, &listener).await.unwrap();
        }));
        (endpoint, task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable Linux Caddy/OpenSSL and loopback network acceptance"]
    async fn create_only_invites_and_hub_errors_keep_secrets_private() {
        let controller = key();
        let (gateway, _ssh) = ssh(&controller, None).await;
        let fixture = HubFixture::start(gateway, &controller).await;
        for name in [None, Some("pending-domain".to_owned())] {
            fixture.take_requests();
            let pending = Host::create(&fixture.hub, name.clone(), 300).await.unwrap();
            assert_eq!(pending.requested_name(), name.as_deref());
            assert_eq!(fixture.take_requests(), ["POST /v2/invites"]);
            assert!(fixture.hub.list_hosts().await.unwrap().is_empty());
        }
        let error = Host::create(&fixture.hub, None, 0).await.unwrap_err();
        assert!(matches!(
            error,
            HostError::Hub(HubClientError::HttpStatus(_))
        ));
        let denied_config = HubConfig {
            token_file: fixture._root.path().join("denied.token"),
            ..fixture.config.clone()
        };
        private_write(&denied_config.token_file, "wrong-secret-token");
        let denied = HubClient::from_config(&denied_config).unwrap();
        let error = Host::create(&denied, None, 300).await.unwrap_err();
        assert!(matches!(
            error,
            HostError::Hub(HubClientError::Unauthorized)
        ));
        assert!(!format!("{error} {error:?}").contains("wrong-secret-token"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable Linux Caddy/OpenSSL and loopback network acceptance"]
    async fn connect_returns_canonical_identity_and_always_resolves_fresh() {
        let controller = key();
        let (target, _target) = ssh(&controller, None).await;
        let target_address = (std::net::Ipv4Addr::LOCALHOST, target.port).into();
        let (gateway, _gateway) = ssh(&controller, Some(target_address)).await;
        let fixture = HubFixture::start(gateway, &controller).await;
        let registered = fixture
            .enroll(
                "domain-machine-001",
                "canonical-domain",
                target.host_public_key,
            )
            .await;
        fixture
            .hub
            .set_display_name(&registered, "Display label is not identity")
            .await
            .unwrap();
        for selector in ["canonical-domain", "domain-machine-001", "domain-machine-"] {
            fixture.take_requests();
            let (host, connection) = Host::connect(&fixture.hub, &fixture.config, selector)
                .await
                .unwrap();
            assert_eq!(host.machine_id(), &registered.machine_id);
            assert_eq!(host.name(), "canonical-domain");
            assert_eq!(fixture.take_requests(), ["GET /v2/hosts", "GET /v2/info"]);
            connection.close().await.unwrap();
        }
        let wrong_identity = fixture._root.path().join("unauthorized-controller");
        private_key_file(&wrong_identity, &key());
        let denied_config = HubConfig {
            identity: wrong_identity,
            ..fixture.config.clone()
        };
        let error = Host::connect(&fixture.hub, &denied_config, "canonical-domain")
            .await
            .err()
            .unwrap();
        assert!(matches!(error, HostError::Ssh(_)));
        fixture.hub.revoke(&registered).await.unwrap();
        fixture.take_requests();
        let error = Host::connect(&fixture.hub, &fixture.config, "canonical-domain")
            .await
            .err()
            .unwrap();
        assert!(matches!(error, HostError::Hub(HubClientError::NotFound)));
        assert_eq!(fixture.take_requests(), ["GET /v2/hosts"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable Linux Caddy/OpenSSL and loopback network acceptance"]
    async fn connect_rejects_unknown_ambiguous_routes_and_target_pin_mismatch() {
        let controller = key();
        let (target, _target) = ssh(&controller, None).await;
        let (gateway, _gateway) = ssh(
            &controller,
            Some((std::net::Ipv4Addr::LOCALHOST, target.port).into()),
        )
        .await;
        let fixture = HubFixture::start(gateway, &controller).await;
        fixture
            .enroll("domain-machine-001", "wrong-pin", public_key(&key()))
            .await;
        fixture
            .enroll(
                "domain-machine-002",
                "second-domain",
                target.host_public_key,
            )
            .await;
        for (selector, ambiguous) in [("unknown-domain", false), ("domain-machine-", true)] {
            fixture.take_requests();
            let error = Host::connect(&fixture.hub, &fixture.config, selector)
                .await
                .err()
                .unwrap();
            assert!(match error {
                HostError::Hub(HubClientError::Ambiguous) => ambiguous,
                HostError::Hub(HubClientError::NotFound) => !ambiguous,
                _ => false,
            });
            assert_eq!(fixture.take_requests(), ["GET /v2/hosts"]);
        }
        let invalid_route = HubConfig {
            preferred_gateway: Some("127.0.0.1:1".into()),
            ..fixture.config.clone()
        };
        let error = Host::connect(&fixture.hub, &invalid_route, "wrong-pin")
            .await
            .err()
            .unwrap();
        assert!(matches!(error, HostError::Hub(HubClientError::Invalid(_))));
        let error = Host::connect(&fixture.hub, &fixture.config, "wrong-pin")
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                error,
                HostError::Ssh(SshClientError::Russh(russh::Error::UnknownKey))
            ),
            "mismatched target pin must fail during SSH host-key validation: {error:?}"
        );
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(OPERATOR));
        assert!(!rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[tokio::test]
    async fn no_hub_never_yields_pending_or_registered_host() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let config = HubConfig {
            hub_url: format!("https://{address}"),
            hub_ca_cert: None,
            token_file: root.path().join("operator.token"),
            ssh_user: "agent".into(),
            identity: root.path().join("missing-controller"),
            gateway_identity: root.path().join("missing-gateway"),
            preferred_gateway: None,
        };
        private_write(&config.token_file, OPERATOR);
        let hub = HubClient::from_config(&config).unwrap();
        assert!(matches!(
            Host::create(&hub, None, 300).await,
            Err(HostError::Hub(HubClientError::Request))
        ));
        assert!(matches!(
            Host::connect(&hub, &config, "anything").await,
            Err(HostError::Hub(HubClientError::Request))
        ));
    }
}
