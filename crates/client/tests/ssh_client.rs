use std::{net::SocketAddr, path::PathBuf};

use hostlink::{
    HostSpec,
    connect::{HostConnection, SshClientError},
};

fn spec(user: &str, host_public_key: &str) -> HostSpec {
    HostSpec {
        endpoint: SocketAddr::from(([127, 0, 0, 1], 1)),
        user: user.to_owned(),
        identity: PathBuf::new(),
        host_public_key: host_public_key.to_owned(),
        gateway: None,
    }
}

#[tokio::test]
async fn connect_rejects_invalid_user_before_network_io() {
    let error = HostConnection::connect(&spec("bad user", "ssh-ed25519 invalid"))
        .await
        .err()
        .expect("invalid user must fail closed");
    assert!(matches!(error, SshClientError::Invalid(_)));
}

#[tokio::test]
async fn connect_rejects_missing_or_malformed_host_pin_before_network_io() {
    for pin in ["", "ssh-ed25519 invalid", "ssh-ed25519 AAAA comment extra"] {
        let error = HostConnection::connect(&spec("controller", pin))
            .await
            .err()
            .expect("invalid pin must fail closed");
        assert!(matches!(
            error,
            SshClientError::Invalid(_) | SshClientError::Key(_)
        ));
    }
}
