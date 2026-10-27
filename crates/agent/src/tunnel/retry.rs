use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttemptPhase {
    ConnectHandshake,
    Authentication,
    ReverseForward,
    Established,
}

impl AttemptPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::ConnectHandshake => "connect_handshake",
            Self::Authentication => "authentication",
            Self::ReverseForward => "reverse_forward",
            Self::Established => "established",
        }
    }
}

pub(super) struct AttemptFailure {
    pub(super) error: io::Error,
    pub(super) transient: bool,
    pub(super) phase: AttemptPhase,
    pub(super) uptime: Duration,
    pub(super) forward_accepted: bool,
    pub(super) cancelled: bool,
}

impl AttemptFailure {
    pub(super) fn permanent(error: io::Error, phase: AttemptPhase) -> Self {
        Self {
            error,
            transient: false,
            phase,
            uptime: Duration::ZERO,
            forward_accepted: false,
            cancelled: false,
        }
    }

    pub(super) fn transient(error: io::Error, phase: AttemptPhase) -> Self {
        Self {
            error,
            transient: true,
            phase,
            uptime: Duration::ZERO,
            forward_accepted: false,
            cancelled: false,
        }
    }

    pub(super) fn cancelled(phase: AttemptPhase, uptime: Duration, forward_accepted: bool) -> Self {
        Self {
            error: io::Error::new(io::ErrorKind::Interrupted, "tunnel shutdown requested"),
            transient: false,
            phase,
            uptime,
            forward_accepted,
            cancelled: true,
        }
    }
}

pub(super) fn ssh_failure(error: russh::Error, phase: AttemptPhase) -> AttemptFailure {
    match error {
        russh::Error::UnknownKey => AttemptFailure::permanent(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway host key does not match the configured pin",
            ),
            phase,
        ),
        russh::Error::IO(error) if is_transient_io(&error) => {
            AttemptFailure::transient(error, phase)
        }
        russh::Error::HUP
        | russh::Error::Disconnect
        | russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::RecvError
        | russh::Error::SendError => AttemptFailure::transient(io::Error::other(error), phase),
        error => AttemptFailure::permanent(io::Error::other(error), phase),
    }
}

pub(super) fn jitter_cap_ms(backoff: Duration, maximum: Duration) -> u128 {
    let backoff_ms = backoff.as_millis().min(maximum.as_millis());
    let maximum_ms = maximum.as_millis();
    let window = backoff_ms.saturating_mul(MAX_JITTER_PERCENT) / 100;
    if backoff_ms == maximum_ms {
        // Without a negative window the fleet would synchronize at the cap:
        // after every long failure, everyone retries exactly every 60s.
        window
    } else {
        window.min(maximum_ms.saturating_sub(backoff_ms))
    }
}

pub(super) fn retry_delay(backoff: Duration, maximum: Duration, jitter_ms: u128) -> Duration {
    let backoff_ms = backoff.as_millis().min(maximum.as_millis());
    let jitter_ms = jitter_ms.min(jitter_cap_ms(backoff, maximum));
    let base_ms = if backoff_ms == maximum.as_millis() {
        backoff_ms.saturating_sub(jitter_cap_ms(backoff, maximum))
    } else {
        backoff_ms
    };
    let delay_ms = base_ms.saturating_add(jitter_ms).min(maximum.as_millis());
    Duration::from_millis(delay_ms.min(u64::MAX as u128) as u64)
}

pub(super) fn reset_backoff_after_stable_session(
    backoff: Duration,
    initial: Duration,
    maximum: Duration,
    uptime: Duration,
) -> Duration {
    if uptime >= STABLE_SESSION_RESET {
        initial.min(maximum)
    } else {
        backoff.min(maximum)
    }
}

pub(super) fn error_class(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::BrokenPipe => "broken_pipe",
        _ => "transport_error",
    }
}

pub(super) fn emit_diagnostic(event: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(io::stderr().lock(), "{event}");
}

pub(super) fn is_transient_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::WouldBlock
    )
}
