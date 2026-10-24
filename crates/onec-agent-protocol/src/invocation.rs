//! Canonical, versioned identity of one Agent-owned native durable invocation.

use crate::{NativeExecutionEffect, ResultArtifactSpec, RunLocalJobIdentity, StdinPayload};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Extracts a bounded requested testcase filter from canonical libtest arguments.
///
/// Ambiguous, missing, duplicated, empty, or control-containing selectors are not recognized.
/// Listing and skip options are rejected because they change or bypass the selected cases. The
/// returned value describes only the requested filter: it does not prove that a matching test
/// existed, ran, or passed.
pub fn requested_exact_testcase(args: &[String]) -> Option<&str> {
    if args.iter().any(|argument| {
        argument == "--list" || argument == "--skip" || argument.starts_with("--skip=")
    }) {
        return None;
    }
    let mut exact = args
        .iter()
        .enumerate()
        .filter(|(_, argument)| argument.as_str() == "--exact");
    let (index, _) = exact.next()?;
    if exact.next().is_some() {
        return None;
    }
    let filter = args.get(index.checked_add(1)?)?;
    if filter.trim().is_empty()
        || filter.len() > 4096
        || filter.bytes().any(|byte| byte.is_ascii_control())
        || filter.starts_with('-')
    {
        return None;
    }
    Some(filter)
}

/// Complete non-secret invocation fields bound by a native Agent commitment.
///
/// This identity requires an exact run-local candidate and a closed declared effect.
/// The caller is still responsible for independent target-effect authorization.
/// Its digest is shared between the controller and Agent to prevent a second
/// incompatible serialization of the signed invocation protocol.
pub struct NativeInvocationIdentity<'a> {
    /// Agent-local exact staged executable path.
    pub program: &'a str,
    /// Exact argv, excluding `argv[0]`.
    pub args: &'a [String],
    /// Optional explicitly selected working directory.
    pub cwd: Option<&'a str>,
    /// Non-secret environment overlay.
    pub env: &'a BTreeMap<String, String>,
    /// Optional non-secret stdin bytes.
    pub stdin: Option<&'a StdinPayload>,
    /// Declared results owned by the durable job.
    pub results: &'a [ResultArtifactSpec],
    /// Exact locally staged executable digest and owned run identity.
    pub run_local: &'a RunLocalJobIdentity,
    /// Caller-declared effect, subject to independent target policy.
    pub native_effect: NativeExecutionEffect,
    /// Digest of an independently pinned approved suite policy, when this invocation was
    /// admitted under one. This identifies policy admission only, not executed outcomes.
    pub native_suite_policy_sha256: Option<&'a str>,
}

#[derive(Serialize)]
struct CanonicalInvocationWire<'a> {
    domain: &'static str,
    program: &'a str,
    args: &'a [String],
    cwd: Option<&'a str>,
    env: &'a BTreeMap<String, String>,
    stdin: Option<&'a StdinPayload>,
    results: &'a [ResultArtifactSpec],
    run_local: &'a RunLocalJobIdentity,
    native_effect: NativeExecutionEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_suite_policy_sha256: Option<&'a str>,
}

impl NativeInvocationIdentity<'_> {
    /// SHA-256 of the versioned canonical JSON bytes that the Agent persists
    /// before spawning the worker and rechecks immediately before execution.
    ///
    /// # Errors
    ///
    /// Fails if invocation fields cannot be serialized as canonical JSON.
    pub fn sha256(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&CanonicalInvocationWire {
            domain: if self.native_suite_policy_sha256.is_some() {
                "onec-toolkit:agent:native-invocation-identity:v2"
            } else {
                "onec-toolkit:agent:native-invocation-identity:v1"
            },
            program: self.program,
            args: self.args,
            cwd: self.cwd,
            env: self.env,
            stdin: self.stdin,
            results: self.results,
            run_local: self.run_local,
            native_effect: self.native_effect,
            native_suite_policy_sha256: self.native_suite_policy_sha256,
        })?;
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_exact_testcase_reads_only_one_bounded_libtest_filter() {
        assert_eq!(
            requested_exact_testcase(&[
                "--exact".to_owned(),
                "module::case".to_owned(),
                "--nocapture".to_owned(),
            ]),
            Some("module::case")
        );
        for args in [
            vec!["module::case".to_owned()],
            vec!["--exact".to_owned()],
            vec!["--exact".to_owned(), "".to_owned()],
            vec!["--exact".to_owned(), "--nocapture".to_owned()],
            vec!["--exact".to_owned(), " ".to_owned()],
            vec!["--exact".to_owned(), "one".to_owned(), "--exact".to_owned()],
            vec!["--exact".to_owned(), "bad\nname".to_owned()],
            vec!["--exact".to_owned(), "x".repeat(4097)],
            vec!["--exact".to_owned(), "one".to_owned(), "--list".to_owned()],
            vec![
                "--exact".to_owned(),
                "one".to_owned(),
                "--skip".to_owned(),
                "two".to_owned(),
            ],
            vec![
                "--skip=two".to_owned(),
                "--exact".to_owned(),
                "one".to_owned(),
            ],
        ] {
            assert_eq!(requested_exact_testcase(&args), None, "args: {args:?}");
        }
    }

    #[test]
    fn stable_commitment_changes_with_exact_argv_and_effect() {
        let run = RunLocalJobIdentity::try_new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            format!("sha256-{}.exe", "a".repeat(64)),
            "a".repeat(64),
            Vec::new(),
        )
        .expect("candidate identity");
        let env = BTreeMap::new();
        let args = vec!["--exact".to_owned(), "approved::test".to_owned()];
        let invocation = NativeInvocationIdentity {
            program: "candidate.exe",
            args: &args,
            cwd: Some("owned-root"),
            env: &env,
            stdin: None,
            results: &[],
            run_local: &run,
            native_effect: NativeExecutionEffect::RunOwned,
            native_suite_policy_sha256: None,
        };
        let trusted = invocation.sha256().expect("hash invocation");
        assert_eq!(trusted.len(), 64);
        // Golden hash of the original Agent-private v1 InvocationIdentity JSON:
        // keep compatibility for jobs committed before this protocol ownership move.
        assert_eq!(
            trusted,
            "fedab9152c613d775a7835e10f2f384c18fd6097d29ccd9b616fa3b478abe481"
        );
        assert_eq!(trusted, invocation.sha256().expect("deterministic hash"));
        let altered_args = vec!["--exact".to_owned(), "forged::test".to_owned()];
        assert_ne!(
            trusted,
            NativeInvocationIdentity {
                args: &altered_args,
                ..invocation
            }
            .sha256()
            .expect("hash altered argv")
        );
        assert_ne!(
            trusted,
            NativeInvocationIdentity {
                native_effect: NativeExecutionEffect::Disposable,
                ..invocation
            }
            .sha256()
            .expect("hash altered effect")
        );
    }

    #[test]
    fn commitment_binds_all_nonsecret_launch_fields_and_owned_inputs() {
        let run = RunLocalJobIdentity::try_new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            format!("sha256-{}.exe", "a".repeat(64)),
            "a".repeat(64),
            Vec::new(),
        )
        .expect("valid run-local identity");
        let args = vec!["--exact".to_owned(), "test_one".to_owned()];
        let env = BTreeMap::new();
        let base = NativeInvocationIdentity {
            program: "candidate.exe",
            args: &args,
            cwd: Some("owned-root"),
            env: &env,
            stdin: None,
            results: &[],
            run_local: &run,
            native_effect: NativeExecutionEffect::RunOwned,
            native_suite_policy_sha256: None,
        };
        let expected = base.sha256().expect("baseline digest");

        assert_ne!(
            expected,
            NativeInvocationIdentity {
                native_suite_policy_sha256: Some(&"c".repeat(64)),
                ..base
            }
            .sha256()
            .expect("policy-bound invocation digest"),
        );

        assert_ne!(
            expected,
            NativeInvocationIdentity {
                program: "substituted.exe",
                ..base
            }
            .sha256()
            .expect("program digest"),
        );
        assert_ne!(
            expected,
            NativeInvocationIdentity { cwd: None, ..base }
                .sha256()
                .expect("cwd digest"),
        );
        let mut different_env = BTreeMap::new();
        different_env.insert("INPUT".to_owned(), "changed".to_owned());
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                env: &different_env,
                ..base
            }
            .sha256()
            .expect("environment digest"),
        );

        let stdin = StdinPayload::try_new(vec![0, 1, 2]).expect("non-secret payload");
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                stdin: Some(&stdin),
                ..base
            }
            .sha256()
            .expect("stdin digest"),
        );
        let results = vec![
            ResultArtifactSpec::try_new(
                "result.json".to_owned(),
                64,
                Some("application/json".to_owned()),
            )
            .expect("valid result declaration"),
        ];
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                results: &results,
                ..base
            }
            .sha256()
            .expect("result declaration digest"),
        );

        let different_run = RunLocalJobIdentity::try_new(
            "abcdef0123456789abcdef0123456789".to_owned(),
            format!("sha256-{}.exe", "a".repeat(64)),
            "a".repeat(64),
            Vec::new(),
        )
        .expect("different owned run");
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                run_local: &different_run,
                ..base
            }
            .sha256()
            .expect("run identity digest"),
        );
        let different_exe = RunLocalJobIdentity::try_new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            format!("sha256-{}.exe", "b".repeat(64)),
            "b".repeat(64),
            Vec::new(),
        )
        .expect("different candidate executable");
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                run_local: &different_exe,
                ..base
            }
            .sha256()
            .expect("candidate digest"),
        );
        let mapped = RunLocalJobIdentity::try_new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            format!("sha256-{}.exe", "a".repeat(64)),
            "a".repeat(64),
            vec![
                crate::RunLocalMappedFile::try_new("INPUT_FILE".to_owned(), "c".repeat(64))
                    .expect("valid mapped file"),
            ],
        )
        .expect("identity containing mapped input");
        assert_ne!(
            expected,
            NativeInvocationIdentity {
                run_local: &mapped,
                ..base
            }
            .sha256()
            .expect("mapped input digest"),
        );
    }
}
