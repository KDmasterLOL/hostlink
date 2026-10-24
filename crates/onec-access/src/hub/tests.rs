//! Hub configuration, redaction, legacy-schema, and remote-projection regressions.

use super::*;

#[test]
fn controller_config_rejects_unknown_fields_and_keeps_defaults() {
    let config = HubControllerConfig::new(
        "https://hub.example.test",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    let mut value = serde_json::to_value(&config).expect("serialize config");
    value
        .as_object_mut()
        .unwrap()
        .insert("remote_prt".to_owned(), serde_json::json!(41000));

    let error =
        serde_json::from_value::<HubControllerConfig>(value).expect_err("unknown field must fail");
    let message = error.to_string();
    assert!(message.contains("unknown field"), "{message}");
    assert!(message.contains("remote_prt"), "{message}");

    let minimal: HubControllerConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "gateway_host": "gateway.example.test",
        "gateway_user": "operator"
    }))
    .expect("supported older config");
    assert_eq!(minimal.gateways[0].port, 22);
    assert_eq!(minimal.token_env, "ONEC_HUB_OPERATOR_TOKEN");
    assert!(minimal.release_base_url.is_none());
    assert!(
        serde_json::to_value(&minimal)
            .expect("serialize")
            .get("target_max_effects")
            .is_none()
    );
}

#[test]
fn legacy_target_effects_are_validated_but_not_persisted() {
    let config = HubControllerConfig::new(
        "https://hub.example.test",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    let mut value = serde_json::to_value(&config).expect("serialize");
    value["target_max_effects"] = serde_json::json!({
        "MACHINE-A": "disposable",
        "machine-b": "read-only"
    });
    let decoded: HubControllerConfig = serde_json::from_value(value).expect("read legacy config");
    let current = serde_json::to_value(&decoded).expect("write current config");
    assert!(current.get("target_max_effects").is_none());
    assert_eq!(current["gateways"][0]["host"], "gateway.example.test");
}

#[test]
fn legacy_effect_parser_rejects_invalid_values_and_machine_ids() {
    let malformed_effect = serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "gateway_host": "gateway.example.test",
        "gateway_user": "operator",
        "target_max_effects": {"machine-a": "unrestricted"}
    });
    serde_json::from_value::<HubControllerConfig>(malformed_effect)
        .expect_err("unknown effect values must fail closed");

    let invalid = serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "gateway_host": "gateway.example.test",
        "gateway_user": "operator",
        "target_max_effects": {"bad id": "disposable"}
    });
    let error =
        serde_json::from_value::<HubControllerConfig>(invalid).expect_err("invalid machine id");
    assert!(error.to_string().contains("machine id"), "{error}");

    let duplicate = serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "gateway_host": "gateway.example.test",
        "gateway_user": "operator",
        "target_max_effects": {
            "MACHINE-A": "run-owned",
            "machine-a": "disposable"
        }
    });
    let error =
        serde_json::from_value::<HubControllerConfig>(duplicate).expect_err("case collision");
    assert!(
        error.to_string().contains("duplicate machine identity"),
        "{error}"
    );
}

#[test]
fn controller_config_serializes_new_gateway_schema_and_rejects_mixed_schema() {
    let config = HubControllerConfig::new(
        "https://hub.example.test",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    let value = serde_json::to_value(&config).expect("serialize");
    assert_eq!(value["gateways"][0]["host"], "gateway.example.test");
    assert!(value.get("gateway_host").is_none());
    let mixed = serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "gateways": [{"host":"new.example.test","user":"operator","port":22}],
        "gateway_host":"old.example.test",
        "gateway_user":"operator"
    });
    let error = serde_json::from_value::<HubControllerConfig>(mixed).expect_err("mixed schema");
    assert!(error.to_string().contains("either gateways[]"), "{error}");
}

#[test]
fn legacy_controller_config_loads_and_is_written_with_gateways_array() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("controller.json");
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "url": "https://hub.example.test",
            "gateway_host": "legacy.example.test",
            "gateway_user": "operator",
            "gateway_port": 2200
        }))
        .expect("legacy JSON"),
    )
    .expect("write legacy config");
    let config = HubControllerConfig::load_from(&path).expect("load legacy config");
    assert_eq!(config.gateways[0].host, "legacy.example.test");
    assert_eq!(config.gateways[0].port, 2200);
    config.save_to(&path).expect("write migrated config");
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read new config")).expect("new JSON");
    assert_eq!(value["gateways"][0]["host"], "legacy.example.test");
    assert!(value.get("gateway_host").is_none());
}

#[test]
fn old_hub_info_defaults_to_empty_gateway_topology() {
    let info: HubInfoResponse = serde_json::from_value(serde_json::json!({
        "public_url": "https://hub.example.test"
    }))
    .expect("old hub info");
    assert!(info.gateways.is_empty());
}

#[tokio::test]
async fn old_hub_uses_local_gateway_fallback_and_known_hosts_trust() {
    let mut config = HubControllerConfig::new(
        "https://hub.example.test",
        "legacy.example.test",
        "operator",
    )
    .expect("config");
    config.known_hosts = Some(PathBuf::from("/operator/known_hosts"));
    let info = std::sync::Arc::new(tokio::sync::OnceCell::new());
    info.set(HubInfoResponse {
        public_url: HubHttpsUrl::parse("https://hub.example.test").expect("URL"),
        gateways: Vec::new(),
    })
    .expect("info cache");
    let client = HubClient {
        config,
        token: "x".repeat(32).into(),
        http: Client::new(),
        info,
    };
    let routes = client.gateway_routes().await.expect("legacy fallback");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].host, "legacy.example.test");
    assert!(
        matches!(&routes[0].trust, crate::GatewayTrust::KnownHosts(path) if path == Path::new("/operator/known_hosts"))
    );
}
use tempfile::tempdir;

#[test]
fn controller_url_fields_remain_json_strings_and_normalize_trailing_slash() {
    let mut config = HubControllerConfig::new(
        "https://hub.example.test/prefix/",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    config.release_base_url = Some(
        HubHttpsUrl::parse("https://downloads.example.test:8443/releases/").expect("release URL"),
    );

    let value = serde_json::to_value(&config).expect("serialize config");
    assert_eq!(value["url"], "https://hub.example.test/prefix");
    assert_eq!(
        value["release_base_url"],
        "https://downloads.example.test:8443/releases"
    );

    let decoded: HubControllerConfig = serde_json::from_value(value).expect("deserialize config");
    assert_eq!(decoded, config);
}

#[test]
fn controller_config_rejects_stringly_https_lookalikes_at_deserialization() {
    for url in [
        "https://".to_owned(),
        ["https://", "user@", "hub.example.test"].concat(),
        "https://hub.example.test?mode=test".to_owned(),
        "https://hub.example.test#fragment".to_owned(),
    ] {
        let value = serde_json::json!({
            "version": 1,
            "url": url,
            "gateway_host": "gateway.example.test",
            "gateway_user": "operator"
        });
        let error = serde_json::from_value::<HubControllerConfig>(value)
            .expect_err("invalid URL must fail at config ingress");
        assert!(error.to_string().contains("onec-hub URL"), "{error}");
    }
}

#[test]
fn release_base_url_is_typed_at_controller_config_ingress() {
    let value = serde_json::json!({
        "version": 1,
        "url": "https://hub.example.test",
        "release_base_url": "https://downloads.example.test/releases?channel=latest",
        "gateway_host": "gateway.example.test",
        "gateway_user": "operator"
    });
    let error = serde_json::from_value::<HubControllerConfig>(value)
        .expect_err("release base query must fail at config ingress");
    assert!(
        error.to_string().contains("must not contain a query"),
        "{error}"
    );
}

#[test]
fn hub_config_round_trip_does_not_store_operator_token() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("hub.json");
    let mut config = HubControllerConfig::new(
        "https://hub.example.test",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    config.identity = Some(PathBuf::from("keys/operator"));
    config.known_hosts = Some(PathBuf::from("keys/known_hosts"));
    config.token_env = "HUB_SECRET".into();
    config.token_file = Some(PathBuf::from("secrets/operator.token"));
    config.save_to(&path).expect("save");
    let text = fs::read_to_string(&path).expect("read");
    assert!(text.contains("HUB_SECRET"));
    assert!(!text.contains("actual-secret-value"));
    let loaded = HubControllerConfig::load_from(&path).expect("load");
    assert_eq!(loaded.identity, Some(dir.path().join("keys/operator")));
    assert_eq!(
        loaded.token_file,
        Some(dir.path().join("secrets/operator.token"))
    );
}

#[test]
fn hub_config_can_read_operator_token_from_private_file() {
    let dir = tempdir().expect("tempdir");
    let token_path = dir.path().join("operator.token");
    let token = "0123456789abcdef0123456789abcdef"; // gitleaks:allow -- fixed test-only credential fixture
    fs::write(&token_path, format!("{token}\n")).expect("token fixture");
    hostlink_core::restrict_private_file(&token_path).expect("private token fixture");
    let mut config = HubControllerConfig::new(
        "https://hub.example.test",
        "gateway.example.test",
        "operator",
    )
    .expect("config");
    config.token_env.clear();
    config.token_file = Some(token_path);
    assert_eq!(config.token().expect("token").expose_secret(), token);
}

#[test]
fn hub_invite_debug_redacts_one_time_token() {
    let invite: HubInvite = serde_json::from_value(serde_json::json!({
        "token": "super-secret-enrollment-token",
        "expires_at": 123,
        "public_url": "https://hub.example.test"
    }))
    .expect("invite");
    assert_eq!(invite.token(), "super-secret-enrollment-token");
    let debug = format!("{invite:?}");
    assert!(!debug.contains(invite.token()));
    assert!(debug.contains("[REDACTED]"));
}

#[tokio::test]
async fn hub_agent_maps_to_runtime_only_control_servers() {
    let config = HubControllerConfig::new(
        "https://hub.example.test",
        "fallback.example.test",
        "operator",
    )
    .expect("config");
    let info = std::sync::Arc::new(tokio::sync::OnceCell::new());
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("gateway key")
        .public_key()
        .to_openssh()
        .expect("gateway key line");
    info.set(HubInfoResponse {
        public_url: HubHttpsUrl::parse("https://hub.example.test").expect("URL"),
        gateways: vec![onec_hub::GatewayEndpoint::new(
            "gateway.example.test",
            "operator",
            key,
        )],
    })
    .expect("initialize info cache");
    let client = HubClient {
        config,
        token: "x".repeat(32).into(),
        http: Client::new(),
        info,
    };
    let agent = HubAgent {
        id: "agent-id".into(),
        machine_id: "machine-id".into(),
        name: "server-a".into(),
        display_name: Some("Тестовый сервер".into()),
        hostname: "SERVER-A".into(),
        username: Some("TIS".into()),
        os: "windows".into(),
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        transport: "open_ssh".into(),
        persistence_mode: Some("user-session".into()),
        remote_port: 41001,
        control_credential_nonce: None,
        legacy_control_secret: Some("0123456789abcdef0123456789abcdef".into()),
        ssh_public_key: "ssh-ed25519 fixture".into(),
        ssh_host_public_key: Some("ssh-ed25519 host-fixture".into()),
        enrolled_at: 1,
        updated_at: 2,
    };
    let control_secret: SecretString = "0123456789abcdef0123456789abcdef".into();

    let ssh = client
        .ssh_control_server_with_secret(&agent, control_secret.clone())
        .await
        .expect("ssh control");
    assert_eq!(ssh.name, "server-a");
    assert_eq!(ssh.remote_port, 41001);
    assert_eq!(ssh.carrier, RemoteCarrier::TargetSsh);
    assert_eq!(ssh.gateways.len(), 1);
    assert_eq!(
        ssh.gateways[0].host, "gateway.example.test",
        "hub topology overrides local fallback"
    );
    assert!(matches!(
        ssh.gateways[0].trust,
        crate::GatewayTrust::PinnedPublicKey(_)
    ));
    assert_eq!(ssh.persistence_mode.as_deref(), Some("user-session"));
    assert_eq!(ssh.target_user.as_deref(), Some("TIS"));
    assert_eq!(
        ssh.target_host_key_alias.as_deref(),
        Some("onec-ops-machine-machine-id")
    );
    assert!(ssh.target_known_hosts.is_some());
    assert_eq!(ssh.secret.expose_secret(), control_secret.expose_secret());

    let direct = client
        .gateway_control_server_with_secret(&agent, control_secret.clone())
        .await
        .expect("gateway control");
    assert_eq!(direct.carrier, RemoteCarrier::GatewayControl);
    assert_eq!(direct.persistence_mode.as_deref(), Some("user-session"));
    assert!(direct.target_user.is_none());
    assert!(direct.target_known_hosts.is_none());

    let (migration_ssh, migration_gateway) = client
        .migration_control_servers(&agent)
        .await
        .expect("migration carrier projections");
    let migration_ssh = migration_ssh.expect("SSH carrier");
    assert_eq!(migration_ssh.carrier, RemoteCarrier::TargetSsh);
    assert_eq!(migration_gateway.carrier, RemoteCarrier::GatewayControl);
    assert_eq!(
        migration_ssh.secret.expose_secret(),
        migration_gateway.secret.expose_secret(),
        "both routes retain the same authenticated control credential"
    );

    let mut gateway_only_agent = agent.clone();
    gateway_only_agent.username = None;
    let (migration_ssh, migration_gateway) = client
        .migration_control_servers(&gateway_only_agent)
        .await
        .expect("missing SSH username only disables the optional carrier");
    assert!(migration_ssh.is_none());
    assert_eq!(migration_gateway.carrier, RemoteCarrier::GatewayControl);

    let mut malformed_agent = agent.clone();
    malformed_agent.remote_port = 0;
    assert!(
        client
            .migration_control_servers(&malformed_agent)
            .await
            .is_err()
    );
    assert!(direct.target_host_key_alias.is_none());
    assert_eq!(
        direct.secret.expose_secret(),
        control_secret.expose_secret()
    );

    let agent_debug = format!("{agent:?}");
    let client_debug = format!("{client:?}");
    let ssh_debug = format!("{ssh:?}");
    let direct_debug = format!("{direct:?}");
    assert!(!agent_debug.contains(control_secret.expose_secret()));
    assert!(!client_debug.contains(client.token.expose_secret()));
    assert!(!ssh_debug.contains(control_secret.expose_secret()));
    assert!(!direct_debug.contains(control_secret.expose_secret()));
    assert!(client_debug.contains("[REDACTED]"));
    assert!(ssh_debug.contains("[REDACTED]"));
    assert!(direct_debug.contains("[REDACTED]"));
}

#[test]
fn regression_inv_061_legacy_hub_agent_without_persistence_mode_is_compatible() {
    let agent: HubAgent = serde_json::from_value(serde_json::json!({
        "id": "agent-id",
        "machine_id": "machine-id",
        "name": "server-a",
        "hostname": "SERVER-A",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.1.0",
        "transport": "open_ssh",
        "remote_port": 41001,
        "control_secret": "0123456789abcdef0123456789abcdef", // gitleaks:allow -- fixed test-only credential fixture
        "ssh_public_key": "ssh-ed25519 fixture",
        "enrolled_at": 1,
        "updated_at": 2
    }))
    .expect("legacy hub agent");
    assert_eq!(agent.persistence_mode, None);
    assert!(agent.control_credential_nonce.is_none());
    let legacy_secret = agent
        .legacy_control_secret
        .as_ref()
        .expect("legacy bulk control secret");
    assert_eq!(
        legacy_secret.expose_secret(),
        "0123456789abcdef0123456789abcdef"
    );
    assert!(!format!("{agent:?}").contains(legacy_secret.expose_secret()));
}

#[test]
fn hub_agent_optional_display_name_accepts_legacy_and_unicode_inventory() {
    let mut raw = serde_json::json!({
        "id": "id",
        "machine_id": "machine-id",
        "name": "server-a",
        "hostname": "SERVER-A",
        "os": "windows",
        "arch": "x86_64",
        "agent_version": "0.3.2",
        "transport": "open_ssh",
        "remote_port": 18400,
        "ssh_public_key": "ssh-ed25519 fixture",
        "enrolled_at": 1,
        "updated_at": 2
    });
    let legacy: HubAgent = serde_json::from_value(raw.clone()).expect("legacy inventory");
    assert_eq!(legacy.display_name, None);
    assert_eq!(legacy.name, "server-a");
    raw["display_name"] = serde_json::json!("Тестовый сервер");
    let labelled: HubAgent = serde_json::from_value(raw).expect("labelled inventory");
    assert_eq!(labelled.display_name.as_deref(), Some("Тестовый сервер"));
    assert_eq!(labelled.name, legacy.name);
    assert_eq!(labelled.machine_id, legacy.machine_id);
}
