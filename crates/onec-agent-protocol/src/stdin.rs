//! Bounded exact-byte stdin payloads for managed process execution.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};
use std::{error::Error, fmt};

/// Maximum raw stdin bytes accepted by one Exec or JobStart request.
///
/// The payload is base64-encoded inside the existing 1 MiB JSON control frame. Keeping the raw
/// ceiling at 256 KiB leaves framing headroom for argv, cwd, environment and authentication.
pub const MAX_STDIN_PAYLOAD_BYTES: usize = 256 * 1024;

const MAX_STDIN_BASE64_BYTES: usize = MAX_STDIN_PAYLOAD_BYTES.div_ceil(3) * 4;

/// Error returned when a caller tries to construct an oversized stdin payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdinPayloadTooLarge {
    actual_bytes: usize,
}

impl StdinPayloadTooLarge {
    /// Returns the rejected raw byte count.
    pub const fn actual_bytes(self) -> usize {
        self.actual_bytes
    }

    /// Returns the protocol-owned raw byte ceiling.
    pub const fn max_bytes(self) -> usize {
        MAX_STDIN_PAYLOAD_BYTES
    }
}

impl fmt::Display for StdinPayloadTooLarge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "stdin payload is {} bytes; maximum is {} bytes",
            self.actual_bytes, MAX_STDIN_PAYLOAD_BYTES
        )
    }
}

impl Error for StdinPayloadTooLarge {}

/// Exact non-secret stdin bytes carried by the authenticated agent control protocol.
///
/// Debug formatting exposes only the byte count. The payload is ordinary input data, not a secret
/// channel; credentials still belong in the dedicated secret-environment contract.
#[derive(Clone, PartialEq, Eq)]
pub struct StdinPayload(Vec<u8>);

impl StdinPayload {
    /// Wraps exact bytes after enforcing the protocol-owned maximum.
    ///
    /// # Errors
    ///
    /// Returns [StdinPayloadTooLarge] when bytes exceeds [MAX_STDIN_PAYLOAD_BYTES].
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, StdinPayloadTooLarge> {
        if bytes.len() > MAX_STDIN_PAYLOAD_BYTES {
            return Err(StdinPayloadTooLarge {
                actual_bytes: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the raw payload byte count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the explicitly supplied payload is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper at the child-process delivery boundary.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for StdinPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdinPayload")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Serialize for StdinPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}

struct StdinPayloadVisitor;

impl Visitor<'_> for StdinPayloadVisitor {
    type Value = StdinPayload;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "base64 stdin payload encoding at most {MAX_STDIN_PAYLOAD_BYTES} raw bytes"
        )
    }

    fn visit_str<E>(self, encoded: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if encoded.len() > MAX_STDIN_BASE64_BYTES {
            return Err(E::custom(format!(
                "stdin base64 payload exceeds encoded maximum of {MAX_STDIN_BASE64_BYTES} bytes"
            )));
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|error| E::custom(format!("invalid stdin base64 payload: {error}")))?;
        StdinPayload::try_new(bytes).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for StdinPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(StdinPayloadVisitor)
    }
}
