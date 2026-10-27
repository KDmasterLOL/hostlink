use super::*;

pub(super) async fn run_managed_https_gateway_fixture(installer_flow: bool) {
    let agent_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_AGENT_BIN").expect("fixture script sets HOSTLINK_AGENT_BIN"),
    );
    let hub_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_HUB_BIN").expect("fixture script sets HOSTLINK_HUB_BIN"),
    );
    let client_bin = PathBuf::from(
        std::env::var_os("HOSTLINK_CLIENT_BIN").expect("fixture script sets HOSTLINK_CLIENT_BIN"),
    );
    let root = tempfile::tempdir().expect("disposable HOME fixture");
    private_dir(root.path());
    let gateway_root = root.path().join("gateway");
    private_dir(&gateway_root);
    let mut children = Children {
        children: Vec::new(),
        stopped: false,
    };
    let old_ssh_pids = Command::new("pgrep")
        .args(["-x", "sshd"])
        .output()
        .expect("snapshot pre-existing sshd process IDs")
        .stdout;
    let old_ssh_port = Command::new("ss")
        .args(["-ltn", "sport", "=", ":22"])
        .output()
        .expect("snapshot pre-existing port 22 listeners")
        .stdout;

    let ssh = ssh::start(root.path(), &gateway_root, &mut children);

    let hub = hub::start(root.path(), &hub_bin, &client_bin, &mut children, &ssh).await;
    https::assert_https_rejections(root.path(), &agent_bin, &hub).await;

    let enrollment_token = root.path().join("enrollment.token");
    let (agent_root, replay_token) = enrollment::enroll_agent(
        enrollment::EnrollmentContext {
            root: root.path(),
            artifact_root: &hub.artifact_root,
            tls_url: &hub.tls_url,
            ca_cert: &hub.ca_cert,
            enrollment_token: &enrollment_token,
            controller_config: &hub.controller_config,
            client_bin: &client_bin,
            cli_config: &hub.cli_config,
            agent_bin: &agent_bin,
            hub_client: &hub.hub_client,
            children: &mut children,
        },
        installer_flow,
    )
    .await;

    if installer_flow {
        use std::os::unix::fs::MetadataExt;
        let installed_root = agent_root
            .parent()
            .expect("Agent state has a private parent");
        let metadata = fs::metadata(installed_root).expect("inspect installed Agent root");
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    let agent_config: serde_json::Value =
        serde_json::from_slice(&fs::read(agent_root.join("agent.json")).unwrap()).unwrap();
    if let Some(token) = replay_token.as_deref() {
        private_write(&enrollment_token, token);
    }
    enrollment::assert_invite_replay(
        &agent_bin,
        &hub.tls_url,
        &hub.ca_cert,
        &enrollment_token,
        root.path(),
    );
    let agent_listen: SocketAddr = agent_config["listen"].as_str().unwrap().parse().unwrap();
    if !installer_flow {
        let mut agent_run = Command::new(&agent_bin);
        agent_run
            .args(["run", "--config"])
            .arg(agent_root.join("agent.json"))
            .stdout(private_log(&root.path().join("agent.stdout.log")))
            .stderr(private_log(&root.path().join("agent.stderr.log")));
        children.start(agent_run);
    }
    wait_port(agent_listen, None);

    // Controller's normal config and CLI use the private CA field and name selector.
    let mut list = Command::new(&client_bin);
    cli_env(&mut list, &hub.cli_config);
    let listed = run_ok(list.args(["list"]), "Hub-backed name inventory");
    assert!(String::from_utf8_lossy(&listed.stdout).contains("managed-fixture"));
    let mut verify = Command::new(&client_bin);
    cli_env(&mut verify, &hub.cli_config);
    let verified = run_ok(
        verify.args(["verify", "managed-fixture"]),
        "Hub-backed host verification through pinned SSH",
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("verified managed-fixture"));
    cli::verify_cli_exec(&client_bin, &hub.cli_config);

    let host = hub
        .hub_client
        .resolve_host_spec("managed-fixture", &hub.controller_config)
        .await
        .expect("resolve live name and pins");
    assert!(
        fs::read_to_string(gateway_root.join("hostlink-v2-authorized_keys"))
            .unwrap()
            .contains("permitlisten=\"127.0.0.1:"),
        "sshd reads the Hub-owned v2 projection file directly"
    );
    let enrolled_public = gateway::exercise_gateway(
        &host,
        &client_bin,
        &hub.cli_config,
        gateway::GatewayFixture {
            root: root.path(),
            agent_root: &agent_root,
            gateway_root: &gateway_root,
            known_hosts: &ssh.test_gateway_known_hosts,
        },
        ssh.ssh_port,
    )
    .await;

    // One-use token replay and TLS failures are exercised above. The Hub's
    // clock/expiry policy is covered by its independent deterministic API
    // tests; do not sleep through a live 60-second token TTL in this fixture.

    // A second sshd process configured on the live gateway port must fail closed.
    let collision_config = root.path().join("sshd_collision_config");
    let collision_config_data = fs::read_to_string(&ssh.sshd_config)
        .unwrap()
        .replace("sshd.pid", "sshd-collision.pid");
    private_write(&collision_config, collision_config_data);
    let collision_log = root.path().join("sshd-collision.stderr.log");
    let mut collision = Command::new(&ssh.sshd_bin);
    collision
        .args(["-D", "-e", "-f"])
        .arg(&collision_config)
        .stdout(Stdio::null())
        .stderr(private_log(&collision_log));
    let mut collision = collision.spawn().expect("start collision probe");
    std::thread::sleep(Duration::from_millis(300));
    let collision_status = collision.try_wait().expect("poll collision probe");
    if collision_status.is_none() {
        let _ = collision.kill();
        let _ = collision.wait();
    }
    assert!(
        collision_status.is_some_and(|status| !status.success()),
        "port collision must prevent a second gateway from starting"
    );
    assert!(
        fs::read_to_string(collision_log)
            .unwrap_or_default()
            .contains("Address already in use"),
        "the second sshd must fail specifically because the selected loopback port is occupied"
    );

    revocation::revoke_and_check_existing_session(
        &hub.hub_client,
        &host,
        &hub.controller_config,
        &client_bin,
        &hub.cli_config,
        &gateway_root,
    )
    .await;
    let sshd_log = fs::read_to_string(root.path().join("sshd.stderr.log"))
        .expect("read private OpenSSH authorization log");
    let enrolled_public_file = root.path().join("enrolled_reverse.pub");
    private_write(&enrolled_public_file, format!("{enrolled_public}\n"));
    let agent_fingerprint = ssh_fingerprint(&enrolled_public_file);
    let controller_public_file = root.path().join("controller.pub");
    private_write(
        &controller_public_file,
        format!("{}\n", public_key(&ssh.operator)),
    );
    let controller_fingerprint = ssh_fingerprint(&controller_public_file);
    assert!(
        sshd_log.contains(&agent_fingerprint),
        "sshd log must record the enrolled Agent key fingerprint"
    );
    assert!(
        sshd_log.contains(&controller_fingerprint),
        "sshd log must record the Controller key fingerprint"
    );
    println!(
        "redacted gateway auth receipt: source_sha={} agent_reverse_key=accepted_from_hub_v2_projection controller_gateway_key=accepted wildcard_reverse=denied revoke_projection=reconciled active_session=not_terminated",
        std::env::var("HOSTLINK_SOURCE_SHA").unwrap_or_else(|_| "unrecorded".into())
    );
    cleanup::stop_fixture_and_check_ssh_baseline(&mut children, &old_ssh_pids, &old_ssh_port).await;
}
