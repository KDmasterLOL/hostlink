use super::hub::HubFixture;
use super::*;

pub(super) async fn assert_https_rejections(root: &Path, agent_bin: &Path, hub: &HubFixture) {
    let wrong_ca_config = HubConfig {
        hub_ca_cert: Some(root.join("wrong-ca.pem")),
        ..hub.controller_config.clone()
    };
    assert!(
        HubClient::from_config(&wrong_ca_config)
            .unwrap()
            .list_hosts()
            .await
            .is_err(),
        "untrusted CA is rejected"
    );
    let wrong_host_config = HubConfig {
        hub_url: format!("https://127.0.0.1:{}", hub.tls_port),
        ..hub.controller_config.clone()
    };
    assert!(
        HubClient::from_config(&wrong_host_config)
            .unwrap()
            .list_hosts()
            .await
            .is_err(),
        "hostname mismatch is rejected"
    );

    // Agent's real enrollment executable first rejects bad CA and wrong-host pins.
    for (label, url, ca) in [
        ("wrong-ca", hub.tls_url.clone(), root.join("wrong-ca.pem")),
        (
            "wrong-host",
            format!("https://127.0.0.1:{}", hub.tls_port),
            hub.ca_cert.clone(),
        ),
    ] {
        let invite = hub
            .hub_client
            .invite(Some(format!("negative-{label}")), 300)
            .await
            .expect("create negative test invite");
        let negative_token = root.join(format!("{label}.token"));
        private_write(&negative_token, invite.token.expose_secret());
        let mut enroll = Command::new(agent_bin);
        enroll
            .args(["enroll", "--hub-url", &url, "--hub-ca-cert"])
            .arg(ca)
            .args(["--token-file"])
            .arg(&negative_token)
            .args(["--root"])
            .arg(root.join(format!("{label}-agent")))
            .args(["--name", &format!("negative-{label}"), "--user"])
            .arg(std::env::var("USER").unwrap());
        assert!(
            !enroll
                .status()
                .expect("run negative Agent enrollment")
                .success(),
            "Agent must reject {label}"
        );
    }
}
