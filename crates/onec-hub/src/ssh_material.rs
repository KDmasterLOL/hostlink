//! Structured OpenSSH public-key parsing for hub enrollment and SSH authorization.

use ssh_key::{Algorithm, PublicKey};
use std::io;

pub(crate) fn normalize_ed25519_public_key(value: &str) -> io::Result<String> {
    if value.contains(['\r', '\n']) {
        return Err(invalid("SSH public key must be a single line"));
    }

    let mut key = PublicKey::from_openssh(value.trim())
        .map_err(|error| invalid(format!("invalid OpenSSH public key: {error}")))?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid(
            "only an OpenSSH ssh-ed25519 public key is accepted",
        ));
    }

    key.set_comment("");
    key.to_openssh()
        .map_err(|error| invalid(format!("failed to normalize OpenSSH public key: {error}")))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti fixture";

    #[test]
    fn normalizes_structurally_valid_ed25519_key_and_drops_comment() {
        assert_eq!(
            normalize_ed25519_public_key(VALID_ED25519).expect("valid key"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti"
        );
    }

    #[test]
    fn rejects_malformed_payload_truncated_wire_wrong_length_and_wrong_algorithm() {
        for key in [
            "ssh-ed25519 !!!not-base64!!!",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAHwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==",
        ] {
            assert!(normalize_ed25519_public_key(key).is_err(), "{key}");
        }
    }

    #[test]
    fn comments_do_not_change_normalized_key_identity() {
        let first = normalize_ed25519_public_key(VALID_ED25519).expect("valid key");
        let second = normalize_ed25519_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti another comment with spaces",
        )
        .expect("same key with other comment");
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_multiline_input() {
        assert!(
            normalize_ed25519_public_key(&format!("{VALID_ED25519}\n{VALID_ED25519}")).is_err()
        );
    }
}
