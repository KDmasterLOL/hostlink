//! Canonical SHA-256 digest value shared by runtime crates.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::io;
use std::str::FromStr;

/// A complete SHA-256 digest represented by the exact 32 bytes compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl FromStr for Sha256Digest {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_data(
                "SHA-256 digest must have 64 hexadecimal characters",
            ));
        }
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(value, &mut digest)
            .map_err(|_| invalid_data("SHA-256 digest must contain only hexadecimal bytes"))?;
        Ok(Self(digest))
    }
}

impl std::fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Sha256Digest {
    /// Constructs a digest directly from its canonical 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete digest bytes in canonical comparison order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(de::Error::custom)
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parsing_and_json_use_canonical_lowercase_wire_text() {
        let parsed = Sha256Digest::from_str(&"A1".repeat(32)).expect("valid digest");
        assert_eq!(parsed.to_string(), "a1".repeat(32));
        assert_eq!(
            serde_json::to_string(&parsed).expect("serialize digest"),
            format!("\"{}\"", "a1".repeat(32))
        );
        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&format!("\"{}\"", "a1".repeat(32)))
                .expect("deserialize digest"),
            parsed
        );
    }

    #[test]
    fn digest_rejects_non_hex_and_incomplete_values() {
        assert_eq!(
            Sha256Digest::from_str(&"a".repeat(63))
                .expect_err("short digest")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(Sha256Digest::from_str(&format!("{}g", "a".repeat(63))).is_err());
    }
}
