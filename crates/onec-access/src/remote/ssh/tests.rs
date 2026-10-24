//! Regression tests for embedded SSH phase, trust and cleanup contracts.

use super::SSH_CONNECT_TIMEOUT;
use super::channel::{attempt_both, finish_cleanup_result, sftp_error_is_no_such_file};
use super::connect::ConnectionCleanupUnconfirmed;
use super::phase::*;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{Status, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[tokio::test]
async fn stalled_gateway_channel_open_times_out_with_safe_diagnostic() {
    let dropped = std::sync::Arc::new(AtomicBool::new(false));
    let dropped_by_future = dropped.clone();
    let started = tokio::time::Instant::now();
    let diagnostic = connection_phase(
        "gateway_direct_tcpip",
        tokio::time::Instant::now() + Duration::from_millis(20),
        async move {
            struct DropSignal(std::sync::Arc<AtomicBool>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _signal = DropSignal(dropped_by_future);
            std::future::pending::<anyhow::Result<()>>().await
        },
    )
    .await
    .expect_err("stalled direct-tcpip open must be bounded")
    .to_string();

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(diagnostic.contains("gateway_direct_tcpip: timed out"));
    assert!(!diagnostic.contains("example.test"));
    assert!(!diagnostic.contains("private-key"));
    assert!(dropped.load(Ordering::SeqCst));

    let diagnostic = connection_phase::<(), _>(
        "gateway_direct_tcpip",
        tokio::time::Instant::now() + Duration::from_secs(1),
        async {
            Err(anyhow::anyhow!(
                "address-marker user-marker private-key-marker"
            ))
        },
    )
    .await
    .expect_err("failed phase returns a classified error")
    .to_string();
    assert!(diagnostic.contains("gateway_direct_tcpip: failed"));
    assert!(!diagnostic.contains("address-marker"));
    assert!(!diagnostic.contains("user-marker"));
    assert!(!diagnostic.contains("private-key-marker"));
}

#[test]
fn regression_inv_794_only_typed_non_trust_route_failures_allow_observation_retry() {
    let transient = SshPhaseFailure::timed_out("gateway_direct_tcpip", 5_000);
    let retryable =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(transient))]);
    assert!(retryable.may_retry_read_only_observation());

    let trust_error = anyhow::Error::from(russh::Error::UnknownKey);
    let host_key_rejection = SshPhaseFailure::failed("gateway_connect", &trust_error, 1);
    assert_eq!(host_key_rejection.outcome(), "host_key_rejected");
    let not_retryable =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(host_key_rejection))]);
    assert!(!not_retryable.may_retry_read_only_observation());

    let transient = SshPhaseFailure::timed_out("gateway_direct_tcpip", 5_000);
    let trust_error = anyhow::Error::from(russh::Error::UnknownKey);
    let host_key_rejection = SshPhaseFailure::failed("gateway_connect", &trust_error, 1);
    let mixed_trust_and_transient = ApprovedRoutesFailure::from_route_failures(&[
        (0, anyhow::Error::new(transient)),
        (1, anyhow::Error::new(host_key_rejection)),
    ]);
    assert!(
        !mixed_trust_and_transient.may_retry_read_only_observation(),
        "one host-key rejection disqualifies the complete approved-route pass"
    );

    let transient = SshPhaseFailure::timed_out("gateway_direct_tcpip", 5_000);
    let opaque_route_failure = ApprovedRoutesFailure::from_route_failures(&[
        (0, anyhow::Error::new(transient)),
        (1, anyhow::anyhow!("untyped route failure")),
    ]);
    assert!(
        !opaque_route_failure.may_retry_read_only_observation(),
        "an opaque route failure disqualifies the complete approved-route pass"
    );

    let non_establishment = SshPhaseFailure::timed_out("target_sftp", 5_000);
    let not_pre_submission =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(non_establishment))]);
    assert!(!not_pre_submission.may_retry_read_only_observation());

    let target_handshake = SshPhaseFailure::timed_out("target_ssh_handshake/auth", 5_000);
    let pre_submission_handshake =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(target_handshake))]);
    assert!(pre_submission_handshake.may_retry_read_only_observation());

    let permanent_auth = SshPhaseFailure::failed(
        "gateway_connect",
        &anyhow::Error::from(russh::Error::NoAuthMethod),
        1,
    );
    assert_eq!(permanent_auth.outcome(), "access_denied");
    let no_transient_route =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(permanent_auth))]);
    assert!(!no_transient_route.may_retry_read_only_observation());

    let prohibited_channel = SshPhaseFailure::failed(
        "target_sftp",
        &anyhow::Error::from(russh::Error::ChannelOpenFailure(
            russh::ChannelOpenFailure::AdministrativelyProhibited,
        )),
        1,
    );
    assert_eq!(prohibited_channel.outcome(), "access_denied");
    let prohibited_routes =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(prohibited_channel))]);
    assert_eq!(
        prohibited_routes.safe_cache_probe_category(),
        "SSH administratively prohibited or unauthorized"
    );

    let channel_failure = SshPhaseFailure::failed(
        "gateway_direct_tcpip",
        &anyhow::Error::from(russh::Error::ChannelOpenFailure(
            russh::ChannelOpenFailure::ConnectFailed,
        )),
        1,
    );
    let transient_channel_failure =
        ApprovedRoutesFailure::from_route_failures(&[(0, anyhow::Error::new(channel_failure))]);
    assert!(transient_channel_failure.may_retry_read_only_observation());
}

#[tokio::test]
async fn regression_inv_205_gateway_channel_open_failure_is_typed_pre_submission() {
    let error = connection_phase(
        "gateway_direct_tcpip",
        tokio::time::Instant::now() + Duration::from_secs(1),
        async {
            Err::<(), _>(anyhow::anyhow!(
                "gateway.example.test private-key=/operator/ssh/identity"
            ))
        },
    )
    .await
    .expect_err("failed gateway channel open returns a typed phase error");
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SshPhaseFailure>())
        .expect("sanitized typed phase error is retained");

    assert_eq!(failure.phase(), "gateway_direct_tcpip");
    assert_eq!(failure.outcome(), "failed");
    assert_eq!(failure.agent_request_submission(), "not_submitted");
    assert_eq!(failure.gateway_status(), "unknown");
    assert!(failure.elapsed_ms() < 1_000);
    assert_eq!(
        serde_json::Value::Object(failure.safe_diagnostic_fields()),
        serde_json::json!({
            "failure_phase": "gateway_direct_tcpip",
            "failure_outcome": "failed",
            "phase_elapsed_ms": failure.elapsed_ms(),
            "agent_request_submission": "not_submitted",
            "gateway_status": "unknown",
        })
    );
    for rendered in [error.to_string(), format!("{error:#}")] {
        assert!(!rendered.contains("gateway.example.test"));
        assert!(!rendered.contains("/operator/ssh/identity"));
    }
}

#[tokio::test]
async fn regression_inv_205_phase_failure_redacts_untrusted_cause_and_preserves_key_rejection() {
    let error = connection_phase(
        "gateway_connect",
        tokio::time::Instant::now() + Duration::from_secs(1),
        async {
            Err::<(), _>(anyhow::anyhow!(
                "gateway.example.test private-key=/operator/ssh/identity fixture-secret"
            ))
        },
    )
    .await
    .expect_err("untrusted SSH message is not emitted");
    for rendered in [error.to_string(), format!("{error:#}")] {
        assert!(rendered.contains("gateway_connect: failed"));
        for forbidden in [
            "gateway.example.test",
            "/operator/ssh/identity",
            "fixture-secret",
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }
    for source in [
        anyhow::Error::from(russh::Error::UnknownKey),
        anyhow::Error::from(russh::keys::Error::KeyChanged { line: 1 }),
    ] {
        let error = connection_phase(
            "target_ssh_handshake/auth",
            tokio::time::Instant::now() + Duration::from_secs(1),
            async { Err::<(), _>(source) },
        )
        .await
        .expect_err("strict known-host mismatch is fatal");
        assert!(error.to_string().contains("host_key_rejected"), "{error}");
        assert!(!format!("{error:#}").contains("line 1"));
    }
}

#[tokio::test]
async fn regression_inv_205_stalled_channel_phase_times_out_without_leaking_source() {
    let failure = connection_phase(
        "gateway_direct_tcpip",
        tokio::time::Instant::now() + Duration::from_millis(10),
        async { std::future::pending::<anyhow::Result<()>>().await },
    )
    .await
    .expect_err("stalled channel must terminate by deadline");
    assert!(
        failure
            .to_string()
            .contains("gateway_direct_tcpip: timed out")
    );
}

#[tokio::test]
async fn regression_inv_205_target_ssh_handshake_uses_configured_connect_budget() {
    let started = tokio::time::Instant::now();
    let error = connection_phase(
        "target_ssh_handshake/auth",
        tokio::time::Instant::now() + SSH_CONNECT_TIMEOUT,
        async { std::future::pending::<anyhow::Result<()>>().await },
    )
    .await
    .expect_err("stalled target SSH handshake must stop at its phase deadline");
    let elapsed = started.elapsed();
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SshPhaseFailure>())
        .expect("timeout retains only the sanitized typed phase failure");

    assert_eq!(failure.phase(), "target_ssh_handshake/auth");
    assert_eq!(failure.outcome(), "timed_out");
    assert!(
        failure.elapsed_ms() >= SSH_CONNECT_TIMEOUT.as_millis() - 100,
        "phase expired early after {} ms",
        failure.elapsed_ms()
    );
    assert!(elapsed <= SSH_CONNECT_TIMEOUT + Duration::from_secs(2));
    assert!(
        error
            .to_string()
            .contains("target_ssh_handshake/auth: timed out")
    );
    assert!(!format!("{error:#}").contains("127.0.0.1"));
}

#[test]
fn only_typed_sftp_no_such_file_proves_absence() {
    fn status_error(status_code: StatusCode) -> SftpError {
        SftpError::Status(Status {
            id: 1,
            status_code,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    assert!(sftp_error_is_no_such_file(&status_error(
        StatusCode::NoSuchFile
    )));
    for error in [
        status_error(StatusCode::PermissionDenied),
        status_error(StatusCode::Failure),
        SftpError::Timeout,
        SftpError::IO("connection reset".to_owned()),
        SftpError::UnexpectedBehavior("malformed response".to_owned()),
    ] {
        assert!(!sftp_error_is_no_such_file(&error));
    }
}

#[test]
fn close_failure_preserves_primary_and_marks_cleanup_unknown() {
    let error = finish_cleanup_result(
        Some(anyhow::anyhow!("sftp close failed")),
        Err(anyhow::anyhow!("target session close pending")),
        Err(anyhow::anyhow!("gateway session close pending")),
    )
    .expect_err("unconfirmed session cleanup must remain an error");

    let chain = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    assert!(
        chain
            .iter()
            .any(|cause| cause.contains("sftp close failed"))
    );
    assert!(
        chain
            .iter()
            .any(|cause| cause.contains("connection cleanup could not be confirmed"))
    );
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<ConnectionCleanupUnconfirmed>()
            .is_some()
    }));
}

#[tokio::test]
async fn gateway_cleanup_is_attempted_after_target_cleanup_failure() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let gateway_attempted = Arc::new(AtomicBool::new(false));
    let gateway_attempted_by_cleanup = Arc::clone(&gateway_attempted);
    let (target, gateway) = attempt_both(
        async { Err(crate::invalid_config("target cleanup pending".to_owned())) },
        async move {
            gateway_attempted_by_cleanup.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;

    assert!(target.is_err());
    assert!(gateway.is_ok());
    assert!(gateway_attempted.load(Ordering::SeqCst));
}
