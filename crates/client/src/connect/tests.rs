use super::*;
use russh::client::Handler;
#[cfg(unix)]
use tempfile::tempdir;

const PINNED_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
const OTHER_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";

#[test]
fn openssh_pin_uses_library_parser_for_comment_and_algorithm() {
    let pin = format!("ssh-ed25519 {PINNED_KEY} two words of comment");
    assert!(gateway::parse_pin(&pin).is_ok());
    assert!(gateway::parse_pin(&format!("{pin}\nssh-ed25519 {OTHER_KEY}")).is_err());
    assert!(gateway::parse_pin(&format!("ssh-rsa {PINNED_KEY}")).is_err());
}

#[tokio::test]
async fn server_key_check_accepts_only_the_pinned_key_bytes() {
    let expected = keys::parse_public_key_base64(PINNED_KEY).expect("valid pinned key");
    let other = keys::parse_public_key_base64(OTHER_KEY).expect("valid alternate key");
    let mut handler = PinHandler {
        expected_key: expected.clone(),
    };

    assert!(
        handler
            .check_server_key(&russh::keys::PublicKeyOrCertificate::from(expected))
            .await
            .expect("key check")
    );
    assert!(
        !handler
            .check_server_key(&russh::keys::PublicKeyOrCertificate::from(other))
            .await
            .expect("key check")
    );
}

#[cfg(unix)]
#[test]
fn identity_loader_rejects_symlinks_and_non_private_modes() {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};

    let directory = tempdir().expect("temporary directory");
    let target = directory.path().join("identity");
    fs::write(&target, b"not a private key").expect("write fixture");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("private mode");
    let link = directory.path().join("identity-link");
    symlink(&target, &link).expect("create symlink");
    assert!(matches!(
        load_identity(&link),
        Err(SshClientError::Invalid(_))
    ));

    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("shared mode");
    assert!(matches!(
        load_identity(&target),
        Err(SshClientError::Invalid(_))
    ));
}

#[cfg(unix)]
#[test]
fn identity_loader_rejects_oversized_files_before_key_parsing() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("large-identity");
    fs::write(&path, vec![b'x'; MAX_IDENTITY_BYTES + 1]).expect("write oversized fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    assert!(matches!(
        load_identity(&path),
        Err(SshClientError::Invalid(_))
    ));
}
