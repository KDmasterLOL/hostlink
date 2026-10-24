//! Secret environment values with redacted debug formatting.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Secret environment overlay serialized on the authenticated control channel.
///
/// Debug formatting exposes only key names and value count, never plaintext values.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretEnvironment(BTreeMap<String, String>);

impl SecretEnvironment {
    /// Wraps an owned secret environment map.
    pub fn new(values: BTreeMap<String, String>) -> Self {
        Self(values)
    }

    /// Returns whether no secret variables are present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and exposes the plaintext map at the execution boundary.
    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }

    /// Iterates secret environment variable names without exposing values.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    /// Iterates plaintext values.
    ///
    /// Callers must keep these values inside the authenticated/execution secret boundary and must
    /// not log or serialize them to untrusted diagnostics.
    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.0.values()
    }
}

impl fmt::Debug for SecretEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvironment")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .field("redacted_values", &self.0.len())
            .finish()
    }
}
