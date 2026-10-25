#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use hostlink::hub::{HubClient, HubClientError, HubConfig};
use hostlink_hub::InviteResponse;
use secrecy::SecretString;

#[test]
fn hub_client_loads_owner_only_token_without_network_io() {
    let root = tempfile::tempdir().unwrap();
    let token_file = root.path().join("operator.token");
    fs::write(&token_file, "fixture-secret\n").unwrap();
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
    let config = HubConfig {
        hub_url: "https://hub.invalid".into(),
        token_file,
        ssh_user: "hostlink".into(),
        identity: PathBuf::from("controller_ed25519"),
        gateway_identity: PathBuf::from("gateway_ed25519"),
    };

    assert!(HubClient::from_config(&config).is_ok());
    assert!(
        HubClient::from_config(&HubConfig {
            hub_url: "http://hub.invalid".into(),
            ..config
        })
        .is_err()
    );
    let invite = InviteResponse {
        token: SecretString::from("fixture-secret"),
        expires_at: 1,
    };
    let debug = format!("{invite:?}");
    assert!(!debug.contains("fixture-secret"));
}

#[cfg(unix)]
#[test]
fn hub_client_rejects_shared_or_linked_token_files() {
    let root = tempfile::tempdir().unwrap();
    let token_file = root.path().join("operator.token");
    fs::write(&token_file, "fixture-secret").unwrap();
    let config = HubConfig {
        hub_url: "https://hub.invalid".into(),
        token_file: token_file.clone(),
        ssh_user: "hostlink".into(),
        identity: PathBuf::from("controller_ed25519"),
        gateway_identity: PathBuf::from("gateway_ed25519"),
    };
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        HubClient::from_config(&config),
        Err(HubClientError::Credential)
    ));

    let link = root.path().join("linked.token");
    std::os::unix::fs::symlink(&token_file, &link).unwrap();
    let linked = HubConfig {
        token_file: link,
        ..config
    };
    assert!(matches!(
        HubClient::from_config(&linked),
        Err(HubClientError::Credential)
    ));
}
