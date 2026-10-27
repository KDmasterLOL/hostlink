use super::*;

pub(super) async fn revoke_and_check_existing_session(
    hub_client: &HubClient,
    host: &hostlink::HostSpec,
    controller_config: &HubConfig,
    client_bin: &Path,
    cli_config: &Path,
    gateway_root: &Path,
) {
    // Revoke while an authenticated session remains: new managed resolution is denied,
    // existing session outcome is reported honestly and the live channel still works.
    let mut established = connect_retry(host).await;
    let enrolled = hub_client.resolve_host("managed-fixture").await.unwrap();
    let receipt = hub_client
        .revoke(&enrolled)
        .await
        .expect("revoke over HTTPS");
    assert!(receipt.revoked_new_connections);
    assert!(!receipt.confirmed_session_terminated && !receipt.remote_uninstall);
    assert!(
        !fs::read_to_string(gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains("hostlink-agent:"),
        "revocation removes the Hub-owned SSH authorization projection"
    );
    assert!(
        hub_client
            .resolve_host_spec("managed-fixture", controller_config)
            .await
            .is_err(),
        "new managed session is refused after revocation"
    );
    let mut revoked_cli = Command::new(client_bin);
    cli_env(&mut revoked_cli, cli_config);
    assert!(
        !revoked_cli
            .args([
                "exec",
                "--host",
                "managed-fixture",
                "--command",
                "printf should-not-run"
            ])
            .status()
            .expect("try fresh managed CLI session after revoke")
            .success(),
        "name-based CLI must refuse a new session after revocation"
    );
    assert_eq!(
        established
            .exec("printf existing-session", &[])
            .await
            .unwrap()
            .stdout,
        b"existing-session",
        "revoke does not claim to terminate an already established session"
    );
    established
        .close()
        .await
        .expect("close established session");
}
