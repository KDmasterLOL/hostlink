//! Real embedded-Agent shell/PTY acceptance, without Hub, production or local user Agent.
#![cfg(unix)]

use hostlink_agent::{AgentConfig, jobs::JobStore, ssh};
use russh::{
    ChannelMsg, Disconnect,
    client::{self, Handler},
    keys::{
        Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate, ssh_key::LineEnding,
    },
};
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

struct Pinned(russh::keys::PublicKey);

impl Handler for Pinned {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        received: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(received.certificate().is_none()
            && received.public_key().key_data() == self.0.key_data())
    }
}

fn private_file(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

async fn expect_ack(channel: &mut russh::Channel<client::Msg>, should_accept: bool) {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) if should_accept => return,
                Some(ChannelMsg::Failure) if !should_accept => return,
                Some(ChannelMsg::Success | ChannelMsg::Failure) => {
                    panic!("SSH shell/PTY request acknowledgement was incorrect")
                }
                None => panic!("SSH closed before request acknowledgement"),
                _ => {}
            }
        }
    })
    .await
    .expect("SSH shell/PTY request must be acknowledged");
}

#[tokio::test]
async fn pinned_agent_pty_shell_streams_and_preserves_exit_status() {
    // The disposable server uses the real Agent SSH handler and its normal
    // process containment; it does not enroll, install, or use the user's Agent.
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let jobs = home.path().join("jobs");
    std::fs::create_dir(&jobs).unwrap();
    std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
    JobStore::initialize_fresh(&jobs)
        .await
        .unwrap()
        .close()
        .await;

    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let controller = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let host_file = home.path().join("host_key");
    let auth_file = home.path().join("authorized_keys");
    private_file(&host_file, host.to_openssh(LineEnding::LF).unwrap());
    private_file(&auth_file, controller.public_key().to_openssh().unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let agent = AgentConfig {
        listen: addr,
        user: "agent".into(),
        host_key: host_file,
        authorized_keys: auth_file,
        jobs_root: jobs,
        board_listen: None,
        gateway: None,
        gateway_alternates: Vec::new(),
    };
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let agent_task = tokio::spawn(async move {
        ssh::serve_on(listener, &agent, async {
            let _ = shutdown.await;
        })
        .await
    });

    let mut session = client::connect(
        Arc::new(client::Config::default()),
        addr,
        Pinned(host.public_key().clone()),
    )
    .await
    .unwrap();
    assert!(
        session
            .authenticate_publickey(
                "agent",
                PrivateKeyWithHashAlg::new(Arc::new(controller), None),
            )
            .await
            .unwrap()
            .success()
    );

    // A shell request without PTY must never acquire an unrestricted child.
    let mut denied = session.channel_open_session().await.unwrap();
    denied.request_shell(true).await.unwrap();
    expect_ack(&mut denied, false).await;

    // Separate new authenticated SSH channel: the PTY is real and sized.
    let mut terminal = session.channel_open_session().await.unwrap();
    terminal
        .request_pty(true, "xterm-256color", 88, 33, 0, 0, &[])
        .await
        .unwrap();
    expect_ack(&mut terminal, true).await;
    terminal.request_shell(true).await.unwrap();
    expect_ack(&mut terminal, true).await;

    // The Agent's shell reads from a live PTY. No pre-buffered stdin file.
    terminal
        .data(&b"echo hostlink-interactive-shell-marker\nstty size\nexit 7\n"[..])
        .await
        .unwrap();

    let (output, code) = tokio::time::timeout(Duration::from_secs(12), async {
        let mut text = Vec::new();
        let mut exit = None;
        loop {
            match terminal.wait().await {
                Some(ChannelMsg::Data { data }) => text.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
                Some(ChannelMsg::Close) | None => return (text, exit),
                Some(ChannelMsg::ExtendedData { data, .. }) => text.extend_from_slice(&data),
                _ => {}
            }
            assert!(text.len() < 65536, "PTY fixture output exceeded limit");
        }
    })
    .await
    .expect("interactive shell did not exit within the test deadline");
    let printed = String::from_utf8_lossy(&output);
    assert!(
        printed.contains("hostlink-interactive-shell-marker"),
        "no real shell output: {printed}"
    );
    assert!(
        printed.contains("33 88"),
        "PTY geometry was not propagated: {printed}"
    );
    assert_eq!(code, Some(7), "must preserve remote shell's exit status");

    session
        .disconnect(Disconnect::ByApplication, "fixture complete", "en")
        .await
        .unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(8), agent_task)
        .await
        .expect("Agent did not shut down after fixture")
        .unwrap()
        .unwrap();
}
