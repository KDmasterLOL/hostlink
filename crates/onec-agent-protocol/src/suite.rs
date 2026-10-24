//! Independently pinned policy for a future Agent-owned native suite runner.

use crate::NativeExecutionEffect;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Match the release-matrix verifier's maximum authenticated suite cardinality.
pub const MAX_NATIVE_SUITE_TESTS: usize = 1_000;
const MAX_NATIVE_SUITE_TEST_NAME_BYTES: usize = 512;

/// Runner launch and complete expected test inventory approved outside the caller.
///
/// The Agent admits this policy only when its canonical digest matches the pin installed in
/// Agent configuration. Admission constrains a process launch; it does not prove that any test
/// case ran or passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSuitePolicy {
    /// Policy schema version. Currently only version 1 is accepted.
    pub version: u32,
    /// SHA-256 of the independently approved runner executable.
    pub runner_sha256: String,
    /// Exact canonical argv, excluding `argv[0]`.
    pub args: Vec<String>,
    /// Exact non-secret environment overlay.
    pub env: BTreeMap<String, String>,
    /// Complete expected test inventory, sorted lexicographically with no duplicates.
    pub expected_tests: Vec<String>,
    /// Closed effect label required for the admitted runner process.
    pub effect: NativeExecutionEffect,
}

impl NativeSuitePolicy {
    /// Validates canonical policy structure and returns its domain-separated SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, malformed digests, noncanonical/empty
    /// inventories, unsafe test names, or an empty argv.
    pub fn sha256(&self) -> Result<String, &'static str> {
        if self.version != 1 {
            return Err("unsupported native suite policy version");
        }
        if self.runner_sha256.len() != 64
            || !self
                .runner_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("native suite runner digest must be lowercase SHA-256");
        }
        if self.args.is_empty() || self.args.iter().any(|arg| arg.contains('\0')) {
            return Err("native suite argv is empty or contains NUL");
        }
        if self.expected_tests.is_empty() || self.expected_tests.len() > MAX_NATIVE_SUITE_TESTS {
            return Err("native suite inventory is empty or exceeds its bound");
        }
        if self.expected_tests.iter().any(|test| {
            test.is_empty()
                || test.len() > MAX_NATIVE_SUITE_TEST_NAME_BYTES
                || test.chars().any(char::is_control)
        }) || self
            .expected_tests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err("native suite inventory must be sorted, unique, and contain valid names");
        }
        let bytes = serde_json::to_vec(&CanonicalNativeSuitePolicy {
            domain: "onec-toolkit:agent:approved-native-suite-policy:v1",
            version: self.version,
            runner_sha256: &self.runner_sha256,
            args: &self.args,
            env: &self.env,
            expected_tests: &self.expected_tests,
            effect: self.effect,
        })
        .map_err(|_| "native suite policy serialization failed")?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Serialize)]
struct CanonicalNativeSuitePolicy<'a> {
    domain: &'static str,
    version: u32,
    runner_sha256: &'a str,
    args: &'a [String],
    env: &'a BTreeMap<String, String>,
    expected_tests: &'a [String],
    effect: NativeExecutionEffect,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NativeSuitePolicy {
        NativeSuitePolicy {
            version: 1,
            runner_sha256: "a".repeat(64),
            args: vec!["run".into(), "--workspace".into()],
            env: BTreeMap::new(),
            expected_tests: vec!["crate::case_a".into(), "crate::case_b".into()],
            effect: NativeExecutionEffect::ReadOnly,
        }
    }

    #[test]
    fn policy_digest_is_canonical_and_binds_all_approved_fields() {
        let policy = policy();
        let digest = policy.sha256().expect("valid policy");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, policy.sha256().expect("deterministic digest"));

        let mut changed = policy.clone();
        changed.args.push("--ignored".into());
        assert_ne!(digest, changed.sha256().expect("changed args remain valid"));
        let mut changed = policy.clone();
        changed.env.insert("NEXTEST_FILTER".into(), "case".into());
        assert_ne!(digest, changed.sha256().expect("changed env remains valid"));
        let mut changed = policy.clone();
        changed.expected_tests.push("crate::case_c".into());
        assert_ne!(
            digest,
            changed.sha256().expect("changed inventory remains valid")
        );
        let mut changed = policy.clone();
        changed.effect = NativeExecutionEffect::RunOwned;
        assert_ne!(
            digest,
            changed.sha256().expect("changed effect remains valid")
        );
    }

    #[test]
    fn policy_rejects_empty_zero_duplicate_unsorted_and_unknown_fields() {
        let mut changed = policy();
        changed.expected_tests.clear();
        assert!(changed.sha256().is_err());
        changed.expected_tests = vec!["crate::case_a".into(), "crate::case_a".into()];
        assert!(changed.sha256().is_err());
        changed.expected_tests = vec!["crate::case_b".into(), "crate::case_a".into()];
        assert!(changed.sha256().is_err());
        changed.expected_tests = vec!["crate::case_a".into(), "".into()];
        assert!(changed.sha256().is_err());
        changed.expected_tests = vec!["a".repeat(MAX_NATIVE_SUITE_TEST_NAME_BYTES + 1)];
        assert!(changed.sha256().is_err());
        changed.expected_tests = (0..=MAX_NATIVE_SUITE_TESTS)
            .map(|index| format!("case_{index:04}"))
            .collect();
        assert!(changed.sha256().is_err());
        let base = serde_json::json!({
            "version": 1,
            "runner_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "args": ["run"],
            "env": {},
            "expected_tests": ["case"],
            "effect": "read-only"
        });
        for (field, claim) in [
            ("caller_claimed_pass", serde_json::json!(true)),
            ("selected_tests", serde_json::json!(["case"])),
            ("executed_tests", serde_json::json!(["case"])),
            ("terminal_statuses", serde_json::json!({"case": "passed"})),
            ("filtered_tests", serde_json::json!(0)),
            ("ignored_tests", serde_json::json!(0)),
            ("retry_count", serde_json::json!(0)),
            ("runner_signature", serde_json::json!("forged")),
        ] {
            let mut forged = base.clone();
            forged[field] = claim;
            assert!(
                serde_json::from_value::<NativeSuitePolicy>(forged).is_err(),
                "admission policy must reject caller-authored {field} outcome claims"
            );
        }
    }
}
