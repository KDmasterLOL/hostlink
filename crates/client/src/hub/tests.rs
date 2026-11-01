use super::*;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use hostlink_hub::{
    DisplayNameRequest, EnrollRequest, EnrollResponse, HostsResponse, HubConfig as ServerConfig,
    HubInfo, HubService, MachineId, RevokeReceipt, router,
};
use russh::keys::{Algorithm, PrivateKey};
use secrecy::SecretString;
use std::{collections::BTreeSet, net::SocketAddr};
use tokio::task::JoinHandle;

const OPERATOR_TOKEN: &str = "operator-token-for-hub-client-test-012345";
const EDGE_TOKEN: &str = "gateway-token-for-hub-client-test-012345";

fn host(id: &str, name: &str, display_name: Option<&str>) -> RegisteredHost {
    RegisteredHost {
        machine_id: MachineId::parse(id).expect("valid fixture ID"),
        name: name.into(),
        display_name: display_name.map(str::to_owned),
        hostname: "fixture-host".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeOperatorKey".into(),
        ssh_host_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKey".into(),
        remote_port: 23001,
        enrolled_at: 1,
        updated_at: 1,
    }
}

fn public_key() -> String {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate disposable Ed25519 key")
        .public_key()
        .to_openssh()
        .expect("encode Ed25519 public key")
}

#[cfg(unix)]
#[test]
fn offline_hub_config_read_does_not_require_token_ca_or_ssh_identity() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("hub.json");
    let missing_token = root.path().join("missing-operator-token");
    let missing_ca = root.path().join("missing-private-ca.pem");
    let expected = HubConfig {
        hub_url: "https://hub.example.invalid".into(),
        hub_ca_cert: Some(missing_ca),
        token_file: missing_token.clone(),
        ssh_user: "operator".into(),
        identity: root.path().join("missing-controller-key"),
        gateway_identity: root.path().join("missing-gateway-key"),
        preferred_gateway: None,
    };
    fs::write(&config_path, serde_json::to_vec(&expected).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let offline = HubClient::read_config(&config_path).expect("show must be offline");
    assert_eq!(offline.hub_url, expected.hub_url);
    assert_eq!(offline.token_file, missing_token);
    assert_eq!(offline.hub_ca_cert, expected.hub_ca_cert);
    assert!(
        HubClient::from_file(&config_path).is_err(),
        "connection must still require a real private token"
    );

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(HubClient::read_config(&config_path).is_err());
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.path().join("config-link.json");
    symlink(&config_path, &link).unwrap();
    assert!(HubClient::read_config(&link).is_err());
    fs::write(&config_path, b"{not-json").unwrap();
    assert!(HubClient::read_config(&config_path).is_err());
}

#[test]
fn shared_hub_dtos_enforce_v2_contract_and_preserve_info_forward_compatibility() {
    let info: HubInfo = serde_json::from_value(serde_json::json!({
        "api_version": 2,
        "management": true,
        "gateways": [],
        "execution_transport": "russh",
        "hosts_endpoint": "/v2/hosts",
        "future_capability": true
    }))
    .expect("Hub info accepts additive fields");
    assert!(info.validate().is_ok());

    let unsupported: HubInfo = serde_json::from_value(serde_json::json!({
        "api_version": 3,
        "management": true,
        "gateways": [],
        "execution_transport": "russh",
        "hosts_endpoint": "/v2/hosts"
    }))
    .expect("deserialize versioned info");
    assert!(unsupported.validate().is_err());

    assert!(
        serde_json::from_value::<HostsResponse>(serde_json::json!({
            "hosts": [],
            "unexpected": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DisplayNameRequest>(serde_json::json!({
            "display_name": "Lab",
            "unexpected": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<RevokeReceipt>(serde_json::json!({
            "revoked_new_connections": true,
            "confirmed_session_terminated": false,
            "remote_uninstall": false,
            "authorized_key_projection": "reconciled",
            "unexpected": true
        }))
        .is_err()
    );
}

#[test]
fn gateway_selection_requires_exact_approved_host_and_port() {
    let first = GatewayEndpoint {
        host: "edge-a.example".into(),
        user: "gateway".into(),
        port: 2222,
        host_public_key: public_key(),
    };
    let second = GatewayEndpoint {
        host: "edge-b.example".into(),
        user: "gateway".into(),
        port: 2222,
        host_public_key: public_key(),
    };
    let gateways = vec![first, second];
    assert!(select_primary_gateway(&gateways, None).is_err());
    assert_eq!(
        select_primary_gateway(&gateways, Some("edge-b.example:2222")).unwrap(),
        1
    );
    assert!(select_primary_gateway(&gateways, Some("edge-b.example:2223")).is_err());
    assert!(select_primary_gateway(&gateways, Some("edge-c.example:2222")).is_err());
}

#[test]
fn gateway_inventory_is_bounded_and_rejects_duplicate_identities_and_pins() {
    let pin = public_key();
    let endpoint = GatewayEndpoint {
        host: "edge.example".into(),
        user: "gateway".into(),
        port: 2222,
        host_public_key: pin.clone(),
    };
    assert!(validate_gateway_list(&[endpoint.clone(), endpoint.clone()]).is_err());
    let duplicate_pin = GatewayEndpoint {
        host: "other.example".into(),
        user: "gateway".into(),
        port: 2222,
        host_public_key: pin,
    };
    assert!(validate_gateway_list(&[endpoint.clone(), duplicate_pin]).is_err());
    let many: Vec<_> = (0..17)
        .map(|index| GatewayEndpoint {
            host: format!("edge-{index}.example"),
            user: "gateway".into(),
            port: 2222,
            host_public_key: public_key(),
        })
        .collect();
    assert!(validate_gateway_list(&many).is_err());
}

#[tokio::test]
async fn optional_gateway_dns_outage_does_not_disable_selected_primary() {
    let primary = GatewayEndpoint {
        host: "127.0.0.1".into(),
        user: "gateway".into(),
        port: 2222,
        host_public_key: public_key(),
    };
    let inaccessible = GatewayEndpoint {
        host: "unresolvable-hostlink-test.invalid".into(),
        user: "gateway".into(),
        port: 2223,
        host_public_key: public_key(),
    };
    let reachable = GatewayEndpoint {
        host: "127.0.0.2".into(),
        user: "gateway".into(),
        port: 2224,
        host_public_key: public_key(),
    };
    let config = HubConfig {
        hub_url: "https://hub.fixture".into(),
        hub_ca_cert: None,
        token_file: "unused-token".into(),
        ssh_user: "agent".into(),
        identity: "controller.key".into(),
        gateway_identity: "gateway.key".into(),
        preferred_gateway: Some("127.0.0.1:2222".into()),
    };
    let mut registered = host("machine-001", "fixture-host", None);
    registered.ssh_host_public_key = public_key();
    let spec = host_spec_from_approved_routes(
        registered.clone(),
        &[primary.clone(), inaccessible.clone(), reachable.clone()],
        &config,
    )
    .await
    .expect("unreachable approved secondary must not block a valid primary");
    let gateway = spec.gateway.expect("pinned gateway");
    assert_eq!(gateway.address, "127.0.0.1:2222".parse().unwrap());
    assert_eq!(gateway.alternates.len(), 1);
    assert_eq!(
        gateway.alternates[0].address,
        "127.0.0.2:2224".parse().unwrap()
    );
    assert_eq!(
        gateway.alternates[0].host_public_key,
        reachable.host_public_key
    );

    let selected_second = HubConfig {
        preferred_gateway: Some("127.0.0.2:2224".into()),
        ..config.clone()
    };
    let spec = host_spec_from_approved_routes(
        registered.clone(),
        &[primary.clone(), reachable.clone(), inaccessible.clone()],
        &selected_second,
    )
    .await
    .expect("explicitly selected second gateway must remain primary");
    let gateway = spec.gateway.expect("pinned selected gateway");
    assert_eq!(gateway.address, "127.0.0.2:2224".parse().unwrap());
    assert_eq!(gateway.alternates.len(), 1);
    assert_eq!(
        gateway.alternates[0].address,
        "127.0.0.1:2222".parse().unwrap()
    );

    let mut invalid_secondary = inaccessible.clone();
    invalid_secondary.host_public_key = "ssh-ed25519 invalid".into();
    assert!(matches!(
        host_spec_from_approved_routes(
            registered.clone(),
            &[primary.clone(), invalid_secondary],
            &config,
        )
        .await,
        Err(HubClientError::Invalid(_))
    ));

    let mut invalid_host = inaccessible.clone();
    invalid_host.host = "invalid alternate hostname".into();
    assert!(matches!(
        host_spec_from_approved_routes(
            registered.clone(),
            &[primary.clone(), invalid_host],
            &config
        )
        .await,
        Err(HubClientError::Invalid(_))
    ));

    let bad_config = HubConfig {
        preferred_gateway: Some("unresolvable-hostlink-test.invalid:2223".into()),
        ..config
    };
    assert!(matches!(
        host_spec_from_approved_routes(registered, &[primary, inaccessible], &bad_config).await,
        Err(HubClientError::GatewayDns)
    ));
}

fn local_client(base: &str, token: &str, timeout: Duration) -> HubClient {
    HubClient {
        base: Url::parse(base).expect("valid local fixture URL"),
        token: SecretString::from(token.to_owned()),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .build()
            .expect("build fixture HTTP client"),
    }
}

async fn serve(app: Router) -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind disposable local Hub fixture");
    let address = listener.local_addr().expect("read fixture address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve disposable Hub fixture");
    });
    (format!("http://{address}"), task)
}

async fn hub_router(root: &Path) -> Router {
    let gateway_public_key = public_key();
    let operator_public_key = public_key();
    let gateway_dir = root.join("gateway");
    fs::create_dir_all(&gateway_dir).expect("create disposable gateway fixture dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&gateway_dir, fs::Permissions::from_mode(0o700))
            .expect("make gateway fixture dir private");
    }
    let service = HubService::new(ServerConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 1)),
        public_url: "https://hub.fixture".into(),
        state_root: root.join("hostlink-hub-v2"),
        authorized_keys: gateway_dir.join("hostlink-v2-authorized_keys"),
        gateways: vec![GatewayEndpoint {
            host: "127.0.0.1".into(),
            user: "gateway-user".into(),
            port: 22,
            host_public_key: gateway_public_key,
        }],
        operator_ssh_public_keys: vec![operator_public_key],
        operator_token: SecretString::from(OPERATOR_TOKEN),
        gateway_lookup_token: SecretString::from(EDGE_TOKEN),
        port_from: 41000,
        port_to: 41010,
        reserved_ports: BTreeSet::from([41000]),
    })
    .expect("build isolated Hub service");
    router(service)
}

#[test]
fn selector_accepts_canonical_name_full_id_and_unique_id_prefix_only() {
    let hosts = vec![
        host("machine-001", "lab-win7", Some("Windows Lab")),
        host("machine-002", "lab-linux", Some("Linux Lab")),
    ];
    assert_eq!(select_host(&hosts, "lab-win7").unwrap().name, "lab-win7");
    assert_eq!(select_host(&hosts, "machine-001").unwrap().name, "lab-win7");
    assert_eq!(
        select_host(&hosts, "machine-00").unwrap_err().to_string(),
        HubClientError::Ambiguous.to_string()
    );
    assert!(matches!(
        select_host(&hosts, "Windows Lab"),
        Err(HubClientError::NotFound)
    ));
}

#[test]
fn hub_url_requires_a_credential_free_https_origin() {
    assert!(parse_origin("https://hub.example").is_ok());
    for value in [
        "http://hub.example",
        "https://user:secret@hub.example",
        "https://hub.example/v2",
        "https://hub.example/?token=x",
    ] {
        assert!(parse_origin(value).is_err(), "accepted {value}");
    }
}

#[tokio::test]
async fn manages_hosts_through_the_in_process_hub_v2_router() {
    let root = tempfile::tempdir().expect("temp Hub root");
    let app = hub_router(root.path()).await;
    let (base, server) = serve(app).await;
    let client = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(3));

    let gateways = client.info().await.expect("authenticated Hub info");
    assert_eq!(gateways.len(), 1);
    assert!(
        client
            .list_hosts()
            .await
            .expect("empty inventory")
            .is_empty()
    );

    let invite = client
        .invite(Some("fixture-machine".into()), 900)
        .await
        .expect("create invitation through v2 API");
    let agent_key = public_key();
    let host_key = public_key();
    let enrolled: EnrollResponse = client
        .request_json(
            Method::POST,
            "/v2/enroll",
            Some(&EnrollRequest {
                token: invite.token,
                machine_id: MachineId::parse("machine-001").expect("machine ID"),
                name: "fixture-machine".into(),
                hostname: "fixture-host".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
                agent_version: "0.1.0".into(),
                ssh_public_key: agent_key,
                ssh_host_public_key: host_key.clone(),
            }),
        )
        .await
        .expect("enroll disposable host through v2 API");
    assert_eq!(enrolled.host.machine_id.as_str(), "machine-001");

    let selected = client
        .resolve_host("fixture-machine")
        .await
        .expect("resolve by canonical name");
    let spec = host_spec_from_approved_routes(
        selected.clone(),
        &gateways,
        &HubConfig {
            hub_url: "https://hub.fixture".into(),
            hub_ca_cert: None,
            token_file: PathBuf::from("unused-in-fixture"),
            ssh_user: "agent-user".into(),
            identity: PathBuf::from("controller_ed25519"),
            gateway_identity: PathBuf::from("gateway_ed25519"),
            preferred_gateway: None,
        },
    )
    .await
    .expect("resolve pinned HostSpec");
    assert_eq!(spec.user, "agent-user");
    assert_eq!(spec.host_public_key, host_key);
    assert_eq!(
        spec.gateway.as_ref().unwrap().reverse_port,
        selected.remote_port
    );

    let renamed = client
        .set_display_name(&selected, "Fixture host")
        .await
        .expect("rename through typed display-name request");
    assert_eq!(renamed.display_name.as_deref(), Some("Fixture host"));

    let receipt = client.revoke(&renamed).await.expect("revoke managed host");
    assert!(receipt.revoked_new_connections);
    assert!(!receipt.confirmed_session_terminated);
    assert!(!receipt.remote_uninstall);
    assert!(matches!(
        client.resolve_host("fixture-machine").await,
        Err(HubClientError::NotFound)
    ));
    server.abort();
}

#[tokio::test]
async fn hub_http_errors_do_not_follow_redirects_or_expose_response_bodies() {
    let root = tempfile::tempdir().expect("temp Hub root");
    let app = hub_router(root.path()).await;
    let (base, server) = serve(app).await;
    let denied = local_client(&base, "wrong-token", Duration::from_secs(2));
    let error = denied
        .list_hosts()
        .await
        .expect_err("wrong bearer is rejected");
    assert!(matches!(error, HubClientError::Unauthorized));
    assert!(!error.to_string().contains("wrong-token"));
    server.abort();

    let redirect_app = Router::new().route(
        "/v2/hosts",
        get(|| async {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(
                    axum::http::header::LOCATION,
                    "https://elsewhere.invalid/v2/hosts",
                )],
            )
                .into_response()
        }),
    );
    let (base, server) = serve(redirect_app).await;
    let redirect = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(2));
    assert!(matches!(
        redirect.list_hosts().await,
        Err(HubClientError::HttpStatus(StatusCode::TEMPORARY_REDIRECT))
    ));
    server.abort();

    for body in [
        "{".to_owned(),
        format!("{{\"hosts\":[]}}{}", " ".repeat(MAX_BODY_BYTES)),
    ] {
        let body = body.to_owned();
        let app = Router::new().route(
            "/v2/hosts",
            get(move || {
                let body = body.clone();
                async move { (StatusCode::OK, body) }
            }),
        );
        let (base, server) = serve(app).await;
        let malformed = local_client(&base, OPERATOR_TOKEN, Duration::from_secs(2));
        assert!(matches!(
            malformed.list_hosts().await,
            Err(HubClientError::Response)
        ));
        server.abort();
    }

    let slow_app = Router::new().route(
        "/v2/hosts",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            (StatusCode::OK, "{\"hosts\":[]}")
        }),
    );
    let (base, server) = serve(slow_app).await;
    let timed = local_client(&base, OPERATOR_TOKEN, Duration::from_millis(10));
    assert!(matches!(
        timed.list_hosts().await,
        Err(HubClientError::Request)
    ));
    server.abort();
}
