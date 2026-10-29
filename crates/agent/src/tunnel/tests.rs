use super::*;
use russh::keys::ssh_key::LineEnding;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
fn protect_test_fixture(path: &Path, directory: bool) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let owner = windows_permissions::utilities::current_process_sid()
        .expect("read the current Windows fixture owner");
    let sid = ConvertSidToStringSid(&owner).expect("encode fixture owner SID");
    let inheritance = if directory { "OICI" } else { "" };
    let dacl: LocalBox<SecurityDescriptor> =
        format!("D:P(A;{inheritance};FA;;;{})", sid.to_string_lossy())
            .parse()
            .expect("construct current-user private DACL");
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(owner.as_ref()),
        None,
        dacl.dacl(),
        None,
    )
    .expect("set the verified private fixture owner and protected DACL");
}

#[tokio::test]
async fn transient_gateway_loss_retries_until_shutdown() {
    let temp = tempfile::tempdir().expect("private test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private test directory permissions");
    }
    #[cfg(windows)]
    protect_test_fixture(temp.path(), true);

    let identity =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("controller identity");
    let pin = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("gateway pin");
    let identity_path = temp.path().join("identity");
    let pin_path = temp.path().join("gateway.pub");
    std::fs::write(
        &identity_path,
        identity
            .to_openssh(LineEnding::LF)
            .expect("encode controller identity")
            .as_bytes(),
    )
    .expect("write controller identity");
    std::fs::write(
        &pin_path,
        pin.public_key().to_openssh().expect("encode gateway pin"),
    )
    .expect("write gateway pin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))
            .expect("private identity permissions");
        std::fs::set_permissions(&pin_path, std::fs::Permissions::from_mode(0o600))
            .expect("private pin permissions");
    }
    #[cfg(windows)]
    {
        protect_test_fixture(&identity_path, false);
        protect_test_fixture(&pin_path, false);
    }

    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind simulated gateway");
    let gateway_addr = gateway_listener.local_addr().expect("gateway address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_by_server = accepted.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let gateway = tokio::spawn(async move {
        let mut shutdown_tx = Some(shutdown_tx);
        loop {
            let (socket, _) = gateway_listener.accept().await.expect("accept gateway TCP");
            drop(socket); // The gateway is unreachable at SSH protocol level.
            if accepted_by_server.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                let _ = shutdown_tx.take().expect("single shutdown").send(());
            }
        }
    });

    let config = AgentConfig {
        listen: "127.0.0.1:43210".parse().expect("loopback target"),
        user: "agent".into(),
        host_key: temp.path().join("unused-host-key"),
        authorized_keys: temp.path().join("unused-authorized-keys"),
        jobs_root: temp.path().join("unused-jobs"),
        board_listen: None,
        gateway: Some(ReverseGateway {
            host: gateway_addr.ip().to_string(),
            port: gateway_addr.port(),
            user: "gateway-user".into(),
            identity: identity_path,
            host_public_key: pin_path,
            remote_port: 40222,
        }),
        gateway_alternates: Vec::new(),
    };

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        run_with_backoff(
            &config,
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_millis(5),
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("tunnel should wait for explicit shutdown");
    assert!(result.is_ok(), "shutdown result: {result:?}");
    assert!(
        accepted.load(Ordering::SeqCst) >= 3,
        "multiple attempts occurred"
    );
    gateway.abort();
}

#[test]
fn host_key_mismatch_is_classified_as_permanent() {
    let failure = ssh_failure(russh::Error::UnknownKey, AttemptPhase::ConnectHandshake);
    assert!(!failure.transient);
    assert_eq!(failure.error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(failure.phase, AttemptPhase::ConnectHandshake);
    assert_eq!(failure.uptime, Duration::ZERO);
    assert!(!failure.forward_accepted);
}

#[test]
fn transient_io_failure_preserves_error_kind_and_phase() {
    let failure = ssh_failure(
        russh::Error::IO(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "opaque transport details",
        )),
        AttemptPhase::Authentication,
    );
    assert!(failure.transient);
    assert_eq!(failure.error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(failure.phase, AttemptPhase::Authentication);
    assert_eq!(failure.uptime, Duration::ZERO);
}

#[test]
fn retry_delay_is_millisecond_jittered_and_capped() {
    let initial = INITIAL_RECONNECT_BACKOFF;
    let maximum = MAX_RECONNECT_BACKOFF;
    assert_eq!(retry_delay(initial, maximum, 0), Duration::from_secs(1));
    assert_eq!(
        retry_delay(initial, maximum, u128::MAX),
        Duration::from_millis(1250)
    );
    assert_eq!(retry_delay(maximum, maximum, u128::MAX), maximum);
    assert_eq!(
        retry_delay(maximum, maximum, 0),
        Duration::from_secs(45),
        "capped retry delays must retain jitter; do not synchronize a fleet"
    );
    assert_eq!(jitter_cap_ms(maximum, maximum), 15_000);
    assert_eq!(retry_delay(Duration::MAX, maximum, u128::MAX), maximum);
    assert_eq!(jitter_cap_ms(Duration::from_secs(4), maximum), 1000);
}

#[test]
fn retry_budget_stays_bounded_for_thirty_minutes_and_many_agents() {
    let maximum = MAX_RECONNECT_BACKOFF;
    let initial = INITIAL_RECONNECT_BACKOFF;
    let mut delay = initial;
    let mut elapsed = Duration::ZERO;
    let mut attempts = 0_u64;
    while elapsed < Duration::from_secs(30 * 60) {
        // Worst case for attempt frequency is zero jitter.
        elapsed += retry_delay(delay, maximum, 0);
        delay = delay.saturating_mul(2).min(maximum);
        attempts += 1;
    }
    assert!(
        attempts <= 45,
        "30-minute attempts unexpectedly unbounded: {attempts}"
    );
    assert!(
        attempts > 20,
        "budget should exercise capped retries: {attempts}"
    );

    let max_agents = 1000_u64;
    assert!(attempts.saturating_mul(max_agents) <= 45_000);
}

#[test]
fn backoff_resets_only_after_sixty_seconds_of_authenticated_uptime() {
    let initial = Duration::from_secs(1);
    let grown = Duration::from_secs(32);
    let maximum = Duration::from_secs(60);
    assert_eq!(
        reset_backoff_after_stable_session(grown, initial, maximum, Duration::from_secs(59)),
        grown
    );
    assert_eq!(
        reset_backoff_after_stable_session(grown, initial, maximum, Duration::from_secs(60)),
        initial
    );
    assert_eq!(
        reset_backoff_after_stable_session(grown, initial, maximum, Duration::ZERO),
        grown
    );
}

#[test]
fn error_observability_uses_only_bounded_categories() {
    let error = io::Error::new(
        io::ErrorKind::PermissionDenied,
        "/private/path user@host token",
    );
    assert_eq!(error_class(&error), "permission_denied");
    assert!(!error_class(&error).contains("private"));
    assert!(!error_class(&error).contains("host"));
}
