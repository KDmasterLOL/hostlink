//! Cryptographic primitives for hub authentication and per-agent secrets.
//!
//! Keep cryptographic construction in maintained crates. This module owns only
//! the domain-specific message format and textual encoding used by the hub.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn token_digest(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
}

pub(crate) fn derive_control_secret(
    master_key: &SecretString,
    machine_id: &str,
    credential_nonce: Option<&str>,
) -> std::io::Result<SecretString> {
    let mut mac = HmacSha256::new_from_slice(master_key.expose_secret().as_bytes())
        .expect("HMAC-SHA256 accepts keys of any size");
    match credential_nonce {
        Some(nonce) => {
            let nonce = decode_control_credential_nonce(nonce)?;
            mac.update(b"onec-agent-control-v2\0");
            update_len_prefixed(&mut mac, machine_id.as_bytes());
            update_len_prefixed(&mut mac, &nonce);
        }
        None => {
            mac.update(b"onec-agent-control-v1\0");
            mac.update(machine_id.as_bytes());
        }
    }
    let digest = mac.finalize().into_bytes();
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into())
}

fn update_len_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

pub(crate) fn random_control_credential_nonce() -> std::io::Result<String> {
    random_hex_256()
}

pub(crate) fn validate_control_credential_nonce(nonce: &str) -> std::io::Result<()> {
    decode_control_credential_nonce(nonce).map(|_| ())
}

fn decode_control_credential_nonce(nonce: &str) -> std::io::Result<[u8; 32]> {
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent control credential nonce must be 64 lowercase hexadecimal characters",
        ));
    }
    let decoded = hex::decode(nonce).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid agent control credential nonce: {error}"),
        )
    })?;
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

pub(crate) fn random_secret() -> std::io::Result<SecretString> {
    Ok(random_hex_256()?.into())
}

fn random_hex_256() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| std::io::Error::other(format!("OS random source failed: {error}")))?;
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_is_256_bits_encoded_as_lowercase_hex() {
        let secret = random_secret().expect("OS random source");
        let secret = secret.expose_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(secret, &secret.to_ascii_lowercase());
    }

    #[test]
    fn hmac_sha256_matches_known_vector() {
        let mut mac = HmacSha256::new_from_slice(b"key").expect("HMAC key");
        mac.update(b"The quick brown fox jumps over the lazy dog");
        let digest = mac.finalize().into_bytes();
        assert_eq!(
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn control_secret_v2_is_stable_per_nonce_and_rotates_with_nonce() {
        let master: SecretString = "master-key".into();
        let first_nonce = "00".repeat(32);
        let rotated_nonce = "01".repeat(32);
        let first = derive_control_secret(&master, "machine-a", Some(&first_nonce))
            .expect("first derivation");
        let same = derive_control_secret(&master, "machine-a", Some(&first_nonce))
            .expect("same derivation");
        let rotated = derive_control_secret(&master, "machine-a", Some(&rotated_nonce))
            .expect("rotated derivation");

        assert_eq!(first.expose_secret(), same.expose_secret());
        assert_ne!(first.expose_secret(), rotated.expose_secret());
    }

    #[test]
    fn legacy_control_secret_derivation_keeps_v1_message_format() {
        let master: SecretString = "master-key".into();
        let derived = derive_control_secret(&master, "machine-a", None).expect("legacy derivation");
        let mut mac =
            HmacSha256::new_from_slice(master.expose_secret().as_bytes()).expect("HMAC key");
        mac.update(b"onec-agent-control-v1\0machine-a");
        let expected = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(derived.expose_secret(), expected);
    }

    #[test]
    fn control_credential_nonce_is_non_secret_256_bit_lowercase_hex() {
        let nonce = random_control_credential_nonce().expect("OS random source");
        assert_eq!(nonce.len(), 64);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(nonce, nonce.to_ascii_lowercase());
    }

    #[test]
    fn rotating_one_agent_nonce_does_not_change_another_agent_secret() {
        let master: SecretString = "master-key".into();
        let nonce_a = "aa".repeat(32);
        let nonce_b = "bb".repeat(32);
        let agent_b_before =
            derive_control_secret(&master, "machine-b", Some(&nonce_b)).expect("agent b before");
        let _agent_a_rotated =
            derive_control_secret(&master, "machine-a", Some(&nonce_a)).expect("agent a rotated");
        let agent_b_after =
            derive_control_secret(&master, "machine-b", Some(&nonce_b)).expect("agent b after");

        assert_eq!(
            agent_b_before.expose_secret(),
            agent_b_after.expose_secret()
        );
    }

    #[test]
    fn invalid_control_credential_nonce_is_rejected() {
        for nonce in ["", "aa", &"A".repeat(64), &"g".repeat(64)] {
            assert!(
                validate_control_credential_nonce(nonce).is_err(),
                "{nonce:?}"
            );
        }
    }
}
