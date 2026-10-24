//! One-request control-channel transport and target-SSH failure classification.

use crate::remote::PathSha256Probe;
use crate::remote::model::{RemoteAgentClient, RemoteCarrier};
use crate::remote::protocol::{read_response_unbuffered, response_into_kind, write_request};
use crate::remote::ssh::ApprovedRoutesFailure;
use crate::{AppError, AppResult};
use hostlink_protocol::{AgentRequest, AgentRequestKind, AgentResponseKind};
use std::io::Write as _;
use std::time::{Duration, Instant};

const RUN_LOCAL_TIMINGS_ENV: &str = "ONEC_ACCESS_RUN_LOCAL_TIMINGS";

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RequestTiming {
    pub(super) route_channel: Duration,
    pub(super) request_response: Duration,
    pub(super) successful_route_channels: u64,
    pub(super) completed_requests: u64,
}

struct RunLocalExecTimingEvent {
    started: Instant,
    request: RequestTiming,
}

impl RunLocalExecTimingEvent {
    fn from_env() -> Option<Self> {
        Self::from_env_value(std::env::var_os(RUN_LOCAL_TIMINGS_ENV).as_deref())
    }

    fn from_env_value(value: Option<&std::ffi::OsStr>) -> Option<Self> {
        run_local_exec_timing_enabled_value(value).then(|| Self {
            started: Instant::now(),
            request: RequestTiming::default(),
        })
    }
}

fn run_local_exec_timing_enabled_value(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

impl Drop for RunLocalExecTimingEvent {
    fn drop(&mut self) {
        let line = format_run_local_exec_timing(self.started.elapsed(), &self.request);
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

fn format_run_local_exec_timing(total: Duration, request: &RequestTiming) -> String {
    let accounted = request
        .route_channel
        .saturating_add(request.request_response);
    let other = total.saturating_sub(accounted);
    format!(
        "hostlink run-local exec timing (us): total={} route_channel={} request_response={} other={} successful_route_channels={} completed_exec_responses={}",
        total.as_micros(),
        request.route_channel.as_micros(),
        request.request_response.as_micros(),
        other.as_micros(),
        request.successful_route_channels,
        request.completed_requests,
    )
}

impl RemoteAgentClient {
    /// Sends one authenticated typed request over a fresh managed control channel.
    ///
    /// For target-SSH carriers, transport failures are wrapped with target-state-unknown context.
    /// Once the request has been written to the managed target, dropping or canceling this future
    /// leaves the controller unable to observe whether the target applied it. The returned
    /// `target-state-unknown` classification applies only when this future remains alive to observe
    /// a transport failure; it does not cancel target work. Callers that need reconnect/no-replay
    /// semantics must use durable jobs and persisted job IDs instead of canceling an in-flight
    /// mutating RPC.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for channel establishment, protocol I/O/JSON, transport finish,
    /// or remote-agent application failures.
    pub async fn request(&self, kind: AgentRequestKind) -> AppResult<AgentResponseKind> {
        self.request_with_timing(kind, None).await
    }

    pub(super) async fn request_with_timing(
        &self,
        kind: AgentRequestKind,
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<AgentResponseKind> {
        self.request_with_write_lifetime(kind, true, timing).await
    }

    /// Reads durable job state or log tails, retrying one fresh route pass only when all approved
    /// routes failed during typed SSH establishment before any Agent request was submitted.
    ///
    /// The retry is deliberately limited to these idempotent observation request kinds. It does
    /// not replay a request after a channel has been opened or any request bytes may have reached
    /// the Agent.
    pub(crate) async fn request_job_observation(
        &self,
        kind: AgentRequestKind,
    ) -> AppResult<AgentResponseKind> {
        let capability = match &kind {
            AgentRequestKind::RunLocalStatus { .. } => "jobs.local-candidate-v1",
            AgentRequestKind::JobStatus { .. } | AgentRequestKind::JobLogs { .. } => "jobs-v1",
            _ => {
                return Err(crate::invalid_config(
                    "read-only job observation reconnect requires a status or logs request"
                        .to_owned(),
                ));
            }
        };
        let retried_hello = self.require_job_observation_capability(capability).await?;
        match self
            .request_with_write_lifetime(kind.clone(), true, None)
            .await
        {
            Err(error) if !retried_hello && may_retry_pre_submission_route(&error) => {
                self.request_with_write_lifetime(kind, true, None).await
            }
            result => result,
        }
    }

    /// Agent-validated scoped deletion may reissue the same request only when
    /// typed transport evidence proves no Agent request was submitted.
    /// Ambiguous post-submission failures remain terminal.
    pub(in crate::remote) async fn request_scoped_cleanup(
        &self,
        kind: AgentRequestKind,
    ) -> AppResult<AgentResponseKind> {
        debug_assert!(matches!(kind, AgentRequestKind::PathRemoveScoped { .. }));
        retry_pre_submission_route_once(
            || self.request_with_write_lifetime(kind.clone(), true, None),
            may_retry_pre_submission_route,
        )
        .await
    }

    pub(crate) async fn request_path_sha256_classified(
        &self,
        path: String,
    ) -> AppResult<PathSha256Probe> {
        // PathSha256 is read-only. Retry one fresh route pass only when every
        // approved route failed before the Agent request was submitted. Never
        // turn an uncertain cache identity into permission to upload.
        let response = retry_pre_submission_route_once(
            || {
                self.request_raw(
                    AgentRequestKind::PathSha256 { path: path.clone() },
                    true,
                    None,
                )
            },
            may_retry_pre_submission_route,
        )
        .await?;
        if crate::remote::protocol::response_is_path_not_found(&response) {
            return Ok(PathSha256Probe::Missing);
        }
        if crate::remote::protocol::response_is_opaque_failure(&response) {
            let error = response_into_kind(response).err().ok_or_else(|| {
                crate::protocol_error(
                    "opaque path sha256 failure unexpectedly decoded as success".to_owned(),
                )
            })?;
            return Ok(PathSha256Probe::OpaqueFailure(error));
        }
        match response_into_kind(response)? {
            AgentResponseKind::PathSha256 { bytes, sha256 } => {
                Ok(PathSha256Probe::Present(bytes, sha256))
            }
            other => Err(crate::invalid_config(format!(
                "remote agent returned unexpected path sha256 response: {other:?}"
            ))),
        }
    }

    /// Sends one Exec request while keeping the controller write half open until the target
    /// publishes its response.
    ///
    /// The live write half is the ownership signal for immediate remote execution: if the
    /// controller/runner dies, the target observes EOF/reset and cancels the owned process tree.
    pub(in crate::remote) async fn request_owned_exec(
        &self,
        kind: AgentRequestKind,
    ) -> AppResult<AgentResponseKind> {
        debug_assert!(matches!(kind, AgentRequestKind::Exec { .. }));
        let mut timing = RunLocalExecTimingEvent::from_env();
        self.request_with_write_lifetime(
            kind,
            false,
            timing.as_mut().map(|event| &mut event.request),
        )
        .await
    }

    async fn request_with_write_lifetime(
        &self,
        kind: AgentRequestKind,
        close_write_before_response: bool,
        timing: Option<&mut RequestTiming>,
    ) -> AppResult<AgentResponseKind> {
        response_into_kind(
            self.request_raw(kind, close_write_before_response, timing)
                .await?,
        )
    }

    async fn request_raw(
        &self,
        kind: AgentRequestKind,
        close_write_before_response: bool,
        mut timing: Option<&mut RequestTiming>,
    ) -> AppResult<hostlink_protocol::AgentResponse> {
        let secret = self.server.secret()?;
        let request = AgentRequest::new(secret, kind);
        let route_started = timing.as_ref().map(|_| Instant::now());
        let mut channel = self.open_channel().await.map_err(|error| {
            self.target_ssh_transport_error(
                "opening control channel before Agent request submission",
                error,
            )
        })?;
        if let (Some(timing), Some(started)) = (timing.as_deref_mut(), route_started) {
            timing.route_channel += started.elapsed();
            timing.successful_route_channels += 1;
        }
        let request_started = timing.as_ref().map(|_| Instant::now());
        write_request(&mut channel, &request)
            .await
            .map_err(|error| self.target_ssh_transport_error("sending control request", error))?;
        if close_write_before_response {
            channel.close_write().await.map_err(|error| {
                self.target_ssh_transport_error("closing control request", error)
            })?;
        }
        let response = read_response_unbuffered(&mut channel)
            .await
            .map_err(|error| self.target_ssh_transport_error("reading control response", error))?;
        if let (Some(timing), Some(started)) = (timing, request_started) {
            timing.request_response += started.elapsed();
            timing.completed_requests += 1;
        }
        if !close_write_before_response {
            channel.close_write().await.map_err(|error| {
                self.target_ssh_transport_error("closing completed exec request", error)
            })?;
        }
        let transport = channel
            .finish()
            .await
            .map_err(|error| self.target_ssh_transport_error("waiting for control channel", error));
        if response.ok {
            transport?;
        }
        Ok(response)
    }

    pub(in crate::remote) fn target_ssh_transport_error(
        &self,
        phase: &str,
        error: AppError,
    ) -> AppError {
        if self.server.carrier != RemoteCarrier::TargetSsh {
            return error;
        }
        crate::remote_transport_error(self.server.name.clone(), phase.to_owned(), error)
    }
}

/// One bounded reconnect only for typed failures proving that no Agent request
/// was submitted. Callers must independently ensure reissue is safe.
async fn retry_pre_submission_route_once<T, F, Fut>(
    mut probe: F,
    may_retry: impl Fn(&AppError) -> bool,
) -> AppResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = AppResult<T>>,
{
    match probe().await {
        Err(error) if may_retry(&error) => probe().await,
        result => result,
    }
}

pub(super) fn may_retry_pre_submission_route(error: &AppError) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ApprovedRoutesFailure>()
            .is_some_and(ApprovedRoutesFailure::may_retry_read_only_observation)
    })
}

#[cfg(test)]
mod pre_submission_retry_tests {
    use super::retry_pre_submission_route_once;

    #[tokio::test]
    async fn one_pre_submission_route_failure_allows_one_read_only_reconnect() {
        let mut attempts = 0;
        let result = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err(crate::invalid_config("transient route".to_owned()))
                } else {
                    Ok(42)
                })
            },
            |_| true,
        )
        .await
        .expect("the second read-only probe can recover");
        assert_eq!(result, 42);
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn failed_reconnect_is_never_retried_a_third_time() {
        let mut attempts = 0;
        let result = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(Err::<(), _>(crate::invalid_config(
                    "transient route".to_owned(),
                )))
            },
            |_| true,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn definitive_or_untyped_failure_never_reconnects() {
        let mut attempts = 0;
        let result = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(Err::<(), _>(crate::invalid_config(
                    "host key rejected".to_owned(),
                )))
            },
            |_| false,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn owned_scoped_cleanup_reconnects_only_after_pre_submission_failure() {
        use hostlink_protocol::AgentResponseKind;
        let mut attempts = 0;
        let result = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err(crate::invalid_config(
                        "typed pre-submission failure".to_owned(),
                    ))
                } else {
                    Ok(AgentResponseKind::PathRemoved { removed: true })
                })
            },
            |_| true,
        )
        .await
        .expect("scoped cleanup may recover from a proven pre-submission failure");
        assert!(matches!(
            result,
            AgentResponseKind::PathRemoved { removed: true }
        ));
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn ambiguous_post_submission_cleanup_is_never_replayed() {
        let mut attempts = 0;
        let outcome = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(Err::<(), _>(crate::invalid_config(
                    "Agent cleanup request may have been submitted".to_owned(),
                )))
            },
            |_| false,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn successful_identity_probe_is_not_repeated() {
        let mut attempts = 0;
        let result = retry_pre_submission_route_once(
            || {
                attempts += 1;
                std::future::ready(Ok::<_, crate::AppError>((33_u64, "digest")))
            },
            |_| true,
        )
        .await
        .expect("exact identity can be used directly");
        assert_eq!(result, (33, "digest"));
        assert_eq!(attempts, 1);
    }
}

#[cfg(test)]
mod run_local_exec_timing_tests {
    use super::{RequestTiming, format_run_local_exec_timing, run_local_exec_timing_enabled_value};
    use std::time::Duration;

    #[test]
    fn run_local_exec_timing_is_opt_in_and_reports_only_bounded_numeric_fields() {
        assert!(!run_local_exec_timing_enabled_value(None));
        assert!(!run_local_exec_timing_enabled_value(Some(
            std::ffi::OsStr::new("true")
        )));
        assert!(!run_local_exec_timing_enabled_value(Some(
            std::ffi::OsStr::new("0")
        )));
        assert!(run_local_exec_timing_enabled_value(Some(
            std::ffi::OsStr::new("1")
        )));

        let timing = RequestTiming {
            route_channel: Duration::from_micros(20),
            request_response: Duration::from_micros(70),
            successful_route_channels: 1,
            completed_requests: 1,
        };
        assert_eq!(
            format_run_local_exec_timing(Duration::from_micros(100), &timing),
            "hostlink run-local exec timing (us): total=100 route_channel=20 request_response=70 other=10 successful_route_channels=1 completed_exec_responses=1"
        );
        assert_eq!(
            format_run_local_exec_timing(Duration::from_micros(5), &timing)
                .split(" other=")
                .nth(1)
                .and_then(|fields| fields.split_whitespace().next()),
            Some("0"),
            "component timings cannot make the residual negative"
        );
    }
}
