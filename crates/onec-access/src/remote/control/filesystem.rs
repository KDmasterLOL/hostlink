//! Typed remote filesystem primitives that remain toolkit-owned.

use crate::AppResult;
use crate::remote::PathSha256Probe;
use crate::remote::control::request::RequestTiming;
use crate::remote::model::{RemoteAgentClient, RemoteRunLocalPaths};
use crate::remote::ssh::SshPhaseFailure;
use hostlink_protocol::{AgentRequestKind, AgentResponseKind};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::StatusCode;
use std::io;
use std::io::Write as _;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct CacheProbeDiagnostic {
    message: String,
}

pub(crate) fn sftp_not_offered_error() -> crate::AppError {
    CacheProbeDiagnostic {
        message: "TargetSftp subsystem was not offered".to_owned(),
    }
    .into()
}

pub(crate) fn sftp_carrier_unavailable_error() -> crate::AppError {
    CacheProbeDiagnostic {
        message: "TargetSftp unavailable for the selected managed carrier".to_owned(),
    }
    .into()
}

impl RemoteAgentClient {
    /// Reconnects to a durable run-local job using its prepared workspace identity.
    pub async fn run_local_status(
        &self,
        run_id: impl Into<String>,
    ) -> AppResult<AgentResponseKind> {
        self.request_job_observation(AgentRequestKind::RunLocalStatus {
            run_id: run_id.into(),
        })
        .await
    }

    /// Removes a prepared workspace only when no durable job owns its run identity.
    pub async fn abandon_run_local(&self, run_id: impl Into<String>) -> AppResult<bool> {
        self.require_capability("jobs.local-candidate-v1").await?;
        match self
            .request(AgentRequestKind::RunLocalAbandon {
                run_id: run_id.into(),
            })
            .await?
        {
            AgentResponseKind::PathRemoved { removed } => Ok(removed),
            other => Err(crate::invalid_config(format!(
                "remote agent returned unexpected run-local abandon response: {other:?}"
            ))),
        }
    }
    /// Prepares the agent-owned executable cache and one identity-owned run directory.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] if the agent does not support `run-local-v1`, rejects the run
    /// identity, or cannot create the directories.
    pub async fn prepare_run_local(
        &self,
        run_id: impl Into<String>,
    ) -> AppResult<RemoteRunLocalPaths> {
        let mut timing = RunLocalPrepareTimingEvent::from_env();
        self.prepare_run_local_with_timing(run_id.into(), timing.as_mut())
            .await
    }

    pub(in crate::remote) async fn prepare_run_local_with_timing(
        &self,
        run_id: String,
        mut timing: Option<&mut RunLocalPrepareTimingEvent>,
    ) -> AppResult<RemoteRunLocalPaths> {
        self.require_capability_with_timing(
            "run-local-v1",
            timing.as_deref_mut().map(|event| &mut event.capability),
        )
        .await?;
        let response = self
            .request_with_timing(
                AgentRequestKind::RunLocalPrepare {
                    run_id,
                    create_mapped_workspace: false,
                },
                timing.as_deref_mut().map(|event| &mut event.prepare),
            )
            .await?;
        let paths = match response {
            AgentResponseKind::RunLocalPaths {
                cache_root,
                run_root_parent,
                run_root,
            } => RemoteRunLocalPaths {
                cache_root,
                run_root_parent,
                run_root,
            },
            other => {
                return Err(crate::invalid_config(format!(
                    "remote agent returned unexpected run-local preparation response: {other:?}"
                )));
            }
        };
        if let Some(timing) = timing {
            timing.complete = true;
        }
        Ok(paths)
    }

    /// Prepares a durable local-candidate workspace after checking the additive candidate capability.
    pub async fn prepare_run_local_job(
        &self,
        run_id: impl Into<String>,
    ) -> AppResult<RemoteRunLocalPaths> {
        self.require_capability("jobs.local-candidate-v1").await?;
        match self
            .request(AgentRequestKind::RunLocalPrepare {
                run_id: run_id.into(),
                create_mapped_workspace: true,
            })
            .await?
        {
            AgentResponseKind::RunLocalPaths {
                cache_root,
                run_root_parent,
                run_root,
            } => Ok(RemoteRunLocalPaths {
                cache_root,
                run_root_parent,
                run_root,
            }),
            other => Err(crate::invalid_config(format!(
                "remote agent returned unexpected run-local job preparation response: {other:?}"
            ))),
        }
    }

    /// Returns exact byte length and SHA-256 for one remote path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when request/transport fails or the response type is unexpected.
    pub async fn path_sha256(&self, path: impl Into<String>) -> AppResult<(u64, String)> {
        match self
            .request(AgentRequestKind::PathSha256 { path: path.into() })
            .await?
        {
            AgentResponseKind::PathSha256 { bytes, sha256 } => Ok((bytes, sha256)),
            other => Err(crate::invalid_config(format!(
                "remote agent returned unexpected path sha256 response: {other:?}"
            ))),
        }
    }

    /// Returns exact file identity, or `None` only when the selected managed target proves the
    /// path is absent through typed agent `PathNotFound` or pinned target-SFTP `lstat`.
    ///
    /// # Errors
    ///
    /// Returns an error when an opaque agent reply cannot be independently resolved by SFTP, or
    /// when transport/protocol validation fails.
    pub async fn path_sha256_if_present(
        &self,
        path: impl Into<String>,
    ) -> AppResult<Option<(u64, String)>> {
        let path = path.into();
        resolve_path_sha256_probe(
            self.request_path_sha256_classified(path.clone()).await,
            || async { self.target_sftp_path_is_absent(&path).await },
        )
        .await
    }

    /// Removes a remote path only within an explicitly supplied owned root.
    ///
    /// Requires the agent's scoped-remove capability and preserves caller-selected recursive and
    /// missing-ok semantics.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when capability negotiation, request/transport, containment, or
    /// response validation fails.
    pub async fn path_remove_scoped(
        &self,
        root: impl Into<String>,
        path: impl Into<String>,
        recursive: bool,
        missing_ok: bool,
    ) -> AppResult<bool> {
        self.require_capability("filesystem.scoped-remove-v1")
            .await?;
        match self
            .request_scoped_cleanup(AgentRequestKind::PathRemoveScoped {
                root: root.into(),
                path: path.into(),
                recursive,
                missing_ok,
            })
            .await?
        {
            AgentResponseKind::PathRemoved { removed } => Ok(removed),
            other => Err(crate::invalid_config(format!(
                "remote agent returned unexpected scoped path-remove response: {other:?}"
            ))),
        }
    }
}

pub(in crate::remote) struct RunLocalPrepareTimingEvent {
    started: Instant,
    capability: RequestTiming,
    prepare: RequestTiming,
    complete: bool,
}

impl RunLocalPrepareTimingEvent {
    fn from_env() -> Option<Self> {
        Self::from_env_value(std::env::var_os("ONEC_ACCESS_RUN_LOCAL_TIMINGS").as_deref())
    }

    fn from_env_value(value: Option<&std::ffi::OsStr>) -> Option<Self> {
        run_local_timing_enabled_value(value).then(Self::new)
    }

    pub(in crate::remote) fn new() -> Self {
        Self {
            started: Instant::now(),
            capability: RequestTiming::default(),
            prepare: RequestTiming::default(),
            complete: false,
        }
    }

    fn route_channels(&self) -> u64 {
        self.capability.successful_route_channels + self.prepare.successful_route_channels
    }

    #[cfg(all(test, unix))]
    pub(in crate::remote) fn completed_responses(&self) -> (u64, u64) {
        (
            self.capability.completed_requests,
            self.prepare.completed_requests,
        )
    }

    #[cfg(all(test, unix))]
    pub(in crate::remote) fn is_complete(&self) -> bool {
        self.complete
    }

    #[cfg(all(test, unix))]
    pub(in crate::remote) fn successful_route_channels(&self) -> u64 {
        self.route_channels()
    }

    fn route_channel(&self) -> Duration {
        self.capability.route_channel + self.prepare.route_channel
    }

    fn other(&self, total: Duration) -> Duration {
        total.saturating_sub(self.route_channel() + self.prepare.request_response)
    }
}

fn run_local_timing_enabled_value(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

impl Drop for RunLocalPrepareTimingEvent {
    fn drop(&mut self) {
        let total = self.started.elapsed();
        let other = self.other(total);
        let _ = writeln!(
            std::io::stderr().lock(),
            "hostlink run-local prepare timing (us): total={} route_channel={} prepare_request_response={} other={} successful_route_channels={} completed_prepare_requests={} complete={}",
            total.as_micros(),
            self.route_channel().as_micros(),
            self.prepare.request_response.as_micros(),
            other.as_micros(),
            self.route_channels(),
            self.prepare.completed_requests,
            u8::from(self.complete),
        );
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn prepare_timing_is_opt_in() {
        assert!(!run_local_timing_enabled_value(None));
        assert!(!run_local_timing_enabled_value(Some(std::ffi::OsStr::new(
            "0"
        ))));
        assert!(!run_local_timing_enabled_value(Some(std::ffi::OsStr::new(
            "true"
        ))));
        assert!(run_local_timing_enabled_value(Some(std::ffi::OsStr::new(
            "1"
        ))));
    }
}

async fn resolve_path_sha256_probe<F, Fut>(
    probe: AppResult<PathSha256Probe>,
    prove_absent: F,
) -> AppResult<Option<(u64, String)>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = AppResult<bool>>,
{
    let probe = probe.map_err(|error| {
        sanitized_probe_error(format!(
            "Agent PathSha256 probe failed: {}",
            safe_error_category(&error)
        ))
    })?;
    match probe {
        PathSha256Probe::Present(bytes, digest) => Ok(Some((bytes, digest))),
        PathSha256Probe::Missing => Ok(None),
        PathSha256Probe::OpaqueFailure(_agent_error) => match prove_absent().await {
            Ok(true) => Ok(None),
            Ok(false) => Err(sanitized_probe_error(
                "Agent PathSha256 response was opaque; TargetSftp found a cache entry; cache upload skipped".to_owned(),
            )),
            Err(sftp_error) => Err(sanitized_probe_error(format!(
                "Agent PathSha256 response was opaque; TargetSftp absence proof failed: {}; cache upload skipped. Upgrade the Agent for typed PathNotFound support or restore pinned TargetSsh SFTP",
                safe_error_category(&sftp_error)
            ))),
        },
    }
}

fn sanitized_probe_error(message: String) -> crate::AppError {
    CacheProbeDiagnostic { message }.into()
}

fn safe_error_category(error: &crate::AppError) -> &'static str {
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CacheProbeDiagnostic>(),
            Some(CacheProbeDiagnostic { message }) if message == "TargetSftp subsystem was not offered"
        )
    }) {
        return "TargetSftp subsystem was not offered";
    }
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CacheProbeDiagnostic>(),
            Some(CacheProbeDiagnostic { message }) if message == "TargetSftp unavailable for the selected managed carrier"
        )
    }) {
        return "TargetSftp unavailable for the selected managed carrier";
    }

    for cause in error.chain() {
        if let Some(routes) = cause.downcast_ref::<crate::remote::ssh::ApprovedRoutesFailure>() {
            return routes.safe_cache_probe_category();
        }
        if let Some(sftp) = cause.downcast_ref::<SftpError>() {
            match sftp {
                SftpError::Status(status) if status.status_code == StatusCode::PermissionDenied => {
                    return "SFTP permission denied";
                }
                SftpError::Timeout => return "SFTP network timeout",
                _ => return "unclassified SFTP transport error",
            }
        }
        if let Some(phase) = cause.downcast_ref::<SshPhaseFailure>() {
            return match phase.outcome() {
                "access_denied" => "SSH administratively prohibited or unauthorized",
                "timed_out" => "SSH network timeout",
                _ => "SSH transport error",
            };
        }
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return match io_error.kind() {
                io::ErrorKind::PermissionDenied => "transport permission denied",
                io::ErrorKind::TimedOut => "network timeout",
                _ => "network or transport error",
            };
        }
        if let Some(ssh_error) = cause.downcast_ref::<russh::Error>() {
            return match ssh_error {
                russh::Error::ChannelOpenFailure(
                    russh::ChannelOpenFailure::AdministrativelyProhibited,
                ) => "SSH administratively prohibited",
                russh::Error::ConnectionTimeout
                | russh::Error::KeepaliveTimeout
                | russh::Error::InactivityTimeout => "SSH network timeout",
                _ => "SSH network or transport error",
            };
        }
    }
    "unclassified network or transport error"
}

#[cfg(test)]
mod path_sha256_probe_tests {
    use super::{
        SftpError, resolve_path_sha256_probe, safe_error_category, sftp_not_offered_error,
    };
    use crate::remote::PathSha256Probe;
    use russh_sftp::protocol::{Status, StatusCode};

    #[test]
    fn cache_probe_error_categories_are_bounded_and_actionable() {
        let permission_denied = anyhow::Error::new(SftpError::Status(Status {
            id: 1,
            status_code: StatusCode::PermissionDenied,
            error_message: "token=hidden /private/path".to_owned(),
            language_tag: String::new(),
        }));
        assert_eq!(
            safe_error_category(&permission_denied),
            "SFTP permission denied"
        );
        assert_eq!(
            safe_error_category(&anyhow::Error::new(SftpError::Timeout)),
            "SFTP network timeout"
        );
        assert_eq!(
            safe_error_category(&sftp_not_offered_error()),
            "TargetSftp subsystem was not offered"
        );
        assert_eq!(
            safe_error_category(&super::sftp_carrier_unavailable_error()),
            "TargetSftp unavailable for the selected managed carrier"
        );
    }

    #[tokio::test]
    async fn only_opaque_agent_response_uses_independent_sftp_absence_proof() {
        let mut proof_attempts = 0;
        let absent = resolve_path_sha256_probe(
            Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                "remote agent rejected request: failed to hash path".to_owned(),
            ))),
            || async {
                proof_attempts += 1;
                Ok(true)
            },
        )
        .await
        .expect("typed SFTP no-such-file authorizes a cache miss");
        assert_eq!(absent, None);
        assert_eq!(proof_attempts, 1);

        for (name, probe, proof_result, expected_proofs) in [
            (
                "SFTP reports existing path",
                Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                    "legacy response".to_owned(),
                ))),
                Ok(false),
                1,
            ),
            (
                "SFTP permission denied",
                Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                    "legacy response".to_owned(),
                ))),
                Err(crate::invalid_config("permission denied".to_owned())),
                1,
            ),
            (
                "SFTP capability unavailable",
                Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                    "legacy response".to_owned(),
                ))),
                Err(crate::invalid_config(
                    "SFTP subsystem unavailable".to_owned(),
                )),
                1,
            ),
            (
                "SFTP symlink uncertainty",
                Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                    "legacy response".to_owned(),
                ))),
                Err(crate::invalid_config("cache path is a symlink".to_owned())),
                1,
            ),
            (
                "SFTP network timeout",
                Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                    "legacy response".to_owned(),
                ))),
                Err(anyhow::Error::new(SftpError::Timeout)),
                1,
            ),
            (
                "agent transport reset",
                Err(crate::invalid_config("connection reset".to_owned())),
                Ok(true),
                0,
            ),
            (
                "agent permission failure",
                Err(crate::invalid_config("access denied".to_owned())),
                Ok(true),
                0,
            ),
            (
                "malformed protocol response",
                Err(crate::invalid_config("invalid JSON response".to_owned())),
                Ok(true),
                0,
            ),
            (
                "verified hit",
                Ok(PathSha256Probe::Present(17, "a".repeat(64))),
                Ok(true),
                0,
            ),
            (
                "typed agent missing",
                Ok(PathSha256Probe::Missing),
                Ok(true),
                0,
            ),
        ] {
            let mut proof_attempts = 0;
            let result = resolve_path_sha256_probe(probe, || async {
                proof_attempts += 1;
                proof_result
            })
            .await;
            assert_eq!(proof_attempts, expected_proofs, "{name}: SFTP proof count");
            match name {
                "verified hit" => assert_eq!(result.expect(name), Some((17, "a".repeat(64)))),
                "typed agent missing" => assert_eq!(result.expect(name), None),
                _ => assert!(result.is_err(), "{name}"),
            }
        }

        let wrong_carrier = resolve_path_sha256_probe(
            Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                "legacy Agent error contains secret=private".to_owned(),
            ))),
            || async { Err(super::sftp_carrier_unavailable_error()) },
        )
        .await
        .expect_err("a carrier without TargetSftp cannot prove cache absence");
        let wrong_carrier_text = wrong_carrier.to_string();
        assert!(
            wrong_carrier_text.contains("TargetSftp unavailable for the selected managed carrier")
        );
        assert!(!wrong_carrier_text.contains("secret=private"));

        let unknown_sftp = resolve_path_sha256_probe(
            Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                "token=hidden local=/private/file remote=192.0.2.10".to_owned(),
            ))),
            || async {
                Err(anyhow::Error::new(SftpError::UnexpectedBehavior(
                    "mystery=hidden token=private path=/remote/cache/file".to_owned(),
                )))
            },
        )
        .await
        .expect_err("unknown SFTP error must fail closed");
        let rendered = format!("hostlink: {unknown_sftp}");
        assert!(rendered.contains("Agent PathSha256 response was opaque"));
        assert!(rendered.contains("unclassified SFTP transport error"));
        assert!(rendered.contains("cache upload skipped"));
        assert!(rendered.contains("typed PathNotFound support"));
        for secret in ["token=", "hidden", "/private", "192.0.2.10", "/remote/"] {
            assert!(
                !rendered.contains(secret),
                "unexpected {secret}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn regression_1c_794_sftp_timeout_never_admits_legacy_cache_miss() {
        let error = resolve_path_sha256_probe(
            Ok(PathSha256Probe::OpaqueFailure(crate::invalid_config(
                "legacy PathSha256 failure".to_owned(),
            ))),
            || async { Err(anyhow::Error::new(SftpError::Timeout)) },
        )
        .await
        .expect_err("a timed-out absence probe must block cache upload and execution");

        let rendered = error.to_string();
        assert!(rendered.contains("SFTP network timeout"), "{rendered}");
        assert!(rendered.contains("cache upload skipped"), "{rendered}");
        assert!(
            rendered.contains("typed PathNotFound support"),
            "{rendered}"
        );
    }
}
