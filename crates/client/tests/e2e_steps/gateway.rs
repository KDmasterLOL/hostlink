use super::*;

pub(super) struct GatewayFixture<'a> {
    pub(super) root: &'a Path,
    pub(super) agent_root: &'a Path,
    pub(super) gateway_root: &'a Path,
    pub(super) known_hosts: &'a Path,
}

pub(super) async fn exercise_gateway(
    host: &hostlink::HostSpec,
    client_bin: &Path,
    cli_config: &Path,
    fixture: GatewayFixture<'_>,
    ssh_port: u16,
) -> String {
    let enrolled_public = verify_gateway_authorization(host, &fixture).await;
    verify_sftp_transfers(host, client_bin, cli_config, &fixture).await;
    let resumed = gateway_jobs::verify_durable_job(host, &fixture).await;
    gateway_jobs::verify_local_forwarding(resumed).await;
    verify_wildcard_reverse_denied(&fixture, ssh_port).await;
    enrolled_public
}

async fn verify_gateway_authorization(
    host: &hostlink::HostSpec,
    fixture: &GatewayFixture<'_>,
) -> String {
    let machine: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.agent_root.join("machine.json")).unwrap())
            .unwrap();
    let enrolled_public = machine["ssh_public_key"].as_str().unwrap();
    assert!(
        fs::read_to_string(fixture.gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains(enrolled_public),
        "the exact enrolled reverse public key is projected for sshd"
    );
    let wrong = key();
    let wrong_identity = fixture.root.join("wrong-controller");
    private_key_file(&wrong_identity, &wrong);
    let mut wrong_route = host.clone();
    wrong_route.gateway.as_mut().unwrap().identity = wrong_identity;
    assert!(
        HostConnection::connect(&wrong_route).await.is_err(),
        "wrong SSH key is rejected by sshd"
    );
    let mut stale_pin = host.clone();
    stale_pin.host_public_key = public_key(&wrong);
    assert!(
        HostConnection::connect(&stale_pin).await.is_err(),
        "stale nested Agent host pin is rejected"
    );
    enrolled_public.to_owned()
}

async fn verify_sftp_transfers(
    host: &hostlink::HostSpec,
    client_bin: &Path,
    cli_config: &Path,
    fixture: &GatewayFixture<'_>,
) {
    let mut session = connect_retry(host).await;
    let artifact = b"managed-e2e-sftp\0\xff";
    let digest = Sha256::digest(artifact);
    let remote_name = format!(
        "{}.upload",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    session
        .sftp_upload(&remote_name, artifact)
        .await
        .expect("SFTP upload through OpenSSH gateway");
    assert_eq!(
        session
            .sftp_download(&remote_name)
            .await
            .expect("SFTP download through gateway"),
        artifact
    );
    let local_upload = fixture.root.join("controller-upload.bin");
    let local_download = fixture.root.join("controller-download.bin");
    let cli_artifact = b"managed-cli-upload\0\xff";
    let cli_remote = format!("{:x}.upload", Sha256::digest(cli_artifact));
    private_write(&local_upload, cli_artifact);
    let mut upload = Command::new(client_bin);
    cli_env(&mut upload, cli_config);
    run_ok(
        upload
            .args(["upload", "--host", "managed-fixture", "--local"])
            .arg(&local_upload)
            .args(["--remote", cli_remote.as_str()]),
        "managed CLI SFTP upload",
    );
    let mut download = Command::new(client_bin);
    cli_env(&mut download, cli_config);
    run_ok(
        download
            .args([
                "download",
                "--host",
                "managed-fixture",
                "--remote",
                cli_remote.as_str(),
                "--local",
            ])
            .arg(&local_download),
        "managed CLI SFTP download",
    );
    assert_eq!(fs::read(local_download).unwrap(), cli_artifact);
}

async fn verify_wildcard_reverse_denied(fixture: &GatewayFixture<'_>, ssh_port: u16) {
    // Wildcard reverse listening is denied by the projected permitlisten option.
    // Use a free port rather than the Agent's already occupied reverse port,
    // otherwise a simple port collision could masquerade as permitlisten.
    let reverse_port = free_port();
    let mut wildcard = Command::new("ssh")
        .args(["-F", "/dev/null", "-p", &ssh_port.to_string(), "-i"])
        .arg(fixture.agent_root.join("gateway_identity"))
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
        ])
        .arg(format!(
            "UserKnownHostsFile={}",
            fixture.known_hosts.display()
        ))
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N",
            "-R",
        ])
        .arg(format!("0.0.0.0:{reverse_port}:127.0.0.1:22"))
        .arg(format!("{}@127.0.0.1", std::env::var("USER").unwrap()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("attempt forbidden wildcard reverse listen");
    let wildcard_deadline = Instant::now() + Duration::from_secs(5);
    let wildcard_status = loop {
        if let Some(status) = wildcard.try_wait().expect("poll wildcard reverse attempt") {
            break Some(status);
        }
        if Instant::now() >= wildcard_deadline {
            let _ = wildcard.kill();
            let _ = wildcard.wait();
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        wildcard_status.is_some_and(|status| !status.success()),
        "gateway projection must deny wildcard reverse listener"
    );
}
