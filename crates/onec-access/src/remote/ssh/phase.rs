//! Bounded SSH phases and sanitized failure classification.

use std::future::Future;
use std::io;

pub(super) async fn connection_phase<T, F>(
    phase: &'static str,
    deadline: tokio::time::Instant,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let started = tokio::time::Instant::now();
    match tokio::time::timeout_at(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(source)) => {
            Err(SshPhaseFailure::failed(phase, &source, started.elapsed().as_millis()).into())
        }
        Err(_) => Err(SshPhaseFailure::timed_out(phase, started.elapsed().as_millis()).into()),
    }
}

// An SSH failure may contain gateway endpoints, operator paths or authentication
// material in its source chain. Project only a stable, typed category at the
// managed controller boundary; neither Display nor alternate error formatting
// may expose the untrusted chain.
fn safe_phase_outcome(error: &anyhow::Error) -> SshPhaseOutcome {
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<russh::Error>(),
            Some(
                russh::Error::ChannelOpenFailure(
                    russh::ChannelOpenFailure::AdministrativelyProhibited
                ) | russh::Error::NoAuthMethod
            )
        )
    }) {
        SshPhaseOutcome::AccessDenied
    } else if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<russh::Error>(),
            Some(russh::Error::UnknownKey)
        ) || matches!(
            cause.downcast_ref::<russh::keys::Error>(),
            Some(russh::keys::Error::KeyChanged { .. })
        )
    }) {
        SshPhaseOutcome::HostKeyRejected
    } else {
        SshPhaseOutcome::Failed
    }
}

fn safe_transient_phase_failure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| match cause.downcast_ref::<russh::Error>() {
            Some(
                russh::Error::ChannelOpenFailure(
                    russh::ChannelOpenFailure::ConnectFailed
                    | russh::ChannelOpenFailure::ResourceShortage,
                )
                | russh::Error::Disconnect
                | russh::Error::HUP
                | russh::Error::ConnectionTimeout
                | russh::Error::KeepaliveTimeout
                | russh::Error::InactivityTimeout,
            ) => true,
            Some(russh::Error::IO(error)) => is_transient_io_error(error.kind()),
            _ => cause
                .downcast_ref::<io::Error>()
                .is_some_and(|error| is_transient_io_error(error.kind())),
        })
}

fn is_transient_io_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshFailurePhase {
    GatewayDirectTcpip,
    Other(&'static str),
}

impl SshFailurePhase {
    fn from_label(label: &'static str) -> Self {
        if label == "gateway_direct_tcpip" {
            Self::GatewayDirectTcpip
        } else {
            Self::Other(label)
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::GatewayDirectTcpip => "gateway_direct_tcpip",
            Self::Other(label) => label,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshPhaseOutcome {
    Failed,
    TimedOut,
    HostKeyRejected,
    AccessDenied,
}

impl SshPhaseOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::HostKeyRejected => "host_key_rejected",
            Self::AccessDenied => "access_denied",
        }
    }
}

/// Sanitized typed outcome for a bounded embedded-SSH phase.
///
/// The underlying russh error is intentionally not retained: it may contain an endpoint,
/// identity path, username, or authentication detail. Consumers can branch on the phase and
/// outcome without parsing `Display` text or exposing the untrusted source.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
#[doc(hidden)]
pub struct SshPhaseFailure {
    phase: SshFailurePhase,
    outcome: SshPhaseOutcome,
    message: String,
    elapsed_ms: u128,
    transient: bool,
}

impl SshPhaseFailure {
    /// Creates a sanitized failed-phase diagnostic for internal controller reporting.
    #[doc(hidden)]
    pub(super) fn failed(phase: &'static str, error: &anyhow::Error, elapsed_ms: u128) -> Self {
        let phase = SshFailurePhase::from_label(phase);
        let outcome = safe_phase_outcome(error);
        Self {
            phase,
            outcome,
            message: format!(
                "{}: {} after {elapsed_ms} ms",
                phase.label(),
                outcome.label()
            ),
            elapsed_ms,
            transient: safe_transient_phase_failure(error),
        }
    }

    pub(super) fn timed_out(phase: &'static str, elapsed_ms: u128) -> Self {
        let phase = SshFailurePhase::from_label(phase);
        Self {
            phase,
            outcome: SshPhaseOutcome::TimedOut,
            message: format!("{}: timed out after {elapsed_ms} ms", phase.label()),
            elapsed_ms,
            transient: true,
        }
    }

    /// Returns the fixed phase label.
    #[doc(hidden)]
    pub fn phase(&self) -> &'static str {
        self.phase.label()
    }

    /// Returns the sanitized outcome category.
    #[doc(hidden)]
    pub fn outcome(&self) -> &'static str {
        self.outcome.label()
    }

    /// Returns the bounded phase duration in milliseconds.
    #[doc(hidden)]
    pub fn elapsed_ms(&self) -> u128 {
        self.elapsed_ms
    }

    fn is_pre_submission_establishment(&self) -> bool {
        matches!(
            self.phase,
            SshFailurePhase::GatewayDirectTcpip
                | SshFailurePhase::Other("gateway_connect")
                | SshFailurePhase::Other("target_ssh_handshake/auth")
        )
    }

    fn is_transient(&self) -> bool {
        self.outcome == SshPhaseOutcome::TimedOut || self.transient
    }

    fn is_host_key_rejected(&self) -> bool {
        self.outcome == SshPhaseOutcome::HostKeyRejected
    }

    /// Reports whether a gateway channel-open failure occurred before Agent request submission.
    #[doc(hidden)]
    pub fn agent_request_submission(&self) -> &'static str {
        if self.phase == SshFailurePhase::GatewayDirectTcpip {
            "not_submitted"
        } else {
            "unknown"
        }
    }

    /// Returns `unknown`; a channel-open failure does not establish gateway reachability.
    #[doc(hidden)]
    pub fn gateway_status(&self) -> &'static str {
        "unknown"
    }

    /// Returns the bounded diagnostic fields used by the managed-host inventory view.
    #[doc(hidden)]
    pub fn safe_diagnostic_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::from_iter([
            (
                "failure_phase".to_owned(),
                serde_json::json!(self.phase.label()),
            ),
            (
                "failure_outcome".to_owned(),
                serde_json::json!(self.outcome.label()),
            ),
            (
                "phase_elapsed_ms".to_owned(),
                serde_json::json!(self.elapsed_ms),
            ),
            (
                "agent_request_submission".to_owned(),
                serde_json::json!(self.agent_request_submission()),
            ),
            (
                "gateway_status".to_owned(),
                serde_json::json!(self.gateway_status()),
            ),
        ])
    }
}

/// Failure after every configured managed gateway route was tried for one control channel.
///
/// Read-only job observation may make one fresh route pass only when every approved route failed
/// in a typed pre-submission SSH establishment phase, no route rejected a host key, and at least
/// one typed route failure was transient.
#[derive(Debug, thiserror::Error)]
#[error("all approved gateway routes failed during transport establishment: {details}")]
pub(crate) struct ApprovedRoutesFailure {
    details: String,
    retryable_observation: bool,
    cache_probe_category: &'static str,
}

impl ApprovedRoutesFailure {
    pub(super) fn from_route_failures(failures: &[(usize, anyhow::Error)]) -> Self {
        let details = failures
            .iter()
            .map(|(index, error)| format!("gateway[{index}] {error}"))
            .collect::<Vec<_>>()
            .join("; ");
        let typed_route_failures = failures
            .iter()
            .map(|(_, error)| {
                error
                    .chain()
                    .filter_map(|cause| cause.downcast_ref::<SshPhaseFailure>())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let retryable_observation = !typed_route_failures.is_empty()
            && typed_route_failures.iter().all(|phases| {
                phases.len() == 1
                    && !phases[0].is_host_key_rejected()
                    && phases[0].is_pre_submission_establishment()
            })
            && typed_route_failures
                .iter()
                .any(|phases| phases[0].is_transient());
        let cache_probe_category = typed_route_failures
            .iter()
            .flatten()
            .map(|phase| phase.outcome())
            .find_map(|outcome| match outcome {
                "access_denied" => Some("SSH administratively prohibited or unauthorized"),
                "timed_out" => Some("SSH network timeout"),
                "host_key_rejected" => Some("SSH host key validation failed"),
                _ => None,
            })
            .unwrap_or("SSH network or transport error");
        Self {
            details,
            retryable_observation,
            cache_probe_category,
        }
    }

    pub(crate) fn safe_cache_probe_category(&self) -> &'static str {
        self.cache_probe_category
    }

    pub(crate) fn may_retry_read_only_observation(&self) -> bool {
        self.retryable_observation
    }
}
