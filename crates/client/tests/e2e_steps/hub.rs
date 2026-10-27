use super::*;

pub(super) fn hub_config(
    root: &Path,
    listen: SocketAddr,
    tls_url: &str,
    ssh_port: u16,
    reverse_port: u16,
    ssh_key: &str,
    operator_key: &str,
) -> PathBuf {
    let path = root.join("hub.json");
    let value = serde_json::json!({
        "version": 2,
        "listen": listen.to_string(),
        "public_url": tls_url,
        "state_root": root.join("hostlink-hub-v2"),
        "authorized_keys": root.join("gateway/hostlink-v2-authorized_keys"),
        "gateways": [{
            "host": "127.0.0.1", "user": std::env::var("USER").unwrap(),
            "port": ssh_port, "host_public_key": ssh_key
        }],
        "operator_ssh_public_keys": [operator_key],
        "port_from": reverse_port,
        "port_to": reverse_port,
        "reserved_ports": []
    });
    private_write(&path, serde_json::to_vec_pretty(&value).unwrap());
    path
}

pub(super) fn write_caddyfile(
    path: &Path,
    url_port: u16,
    cert: &Path,
    key: &Path,
    hub: SocketAddr,
    artifacts: &Path,
) {
    let content = format!(
        "{{\n  admin off\n  auto_https off\n}}\nhttps://localhost:{url_port} {{\n  bind 127.0.0.1\n  tls {} {}\n  route {{\n    @redirect path /redirect\n    redir @redirect /0.1.0/install-hostlink-agent.sh 302\n    @hub path /v2/*\n    handle @hub {{\n      reverse_proxy http://{}\n    }}\n    handle {{\n      root * {}\n      file_server\n    }}\n  }}\n}}\n",
        cert.display(),
        key.display(),
        hub,
        artifacts.display()
    );
    private_write(path, content);
}

pub(super) struct HubFixture {
    pub(super) tls_port: u16,
    pub(super) tls_url: String,
    pub(super) ca_cert: PathBuf,
    pub(super) artifact_root: PathBuf,
    pub(super) controller_config: HubConfig,
    pub(super) cli_config: PathBuf,
    pub(super) hub_client: HubClient,
}

pub(super) async fn start(
    root: &Path,
    hub_bin: &Path,
    client_bin: &Path,
    children: &mut Children,
    ssh: &ssh::SshFixture,
) -> HubFixture {
    // The v2 projection path is passed directly to this test sshd. It is never copied
    // into ~/.ssh or a system authorized_keys file.
    let hub_listener = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let tls_port = free_port();
    let tls_url = format!("https://localhost:{tls_port}");
    let (ca_cert, leaf_cert, leaf_key) = write_server_certificate(root);
    let artifact_root = std::env::var_os("HOSTLINK_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .expect("fixture script packages immutable Agent artifacts");
    let tls_config = root.join("Caddyfile");
    write_caddyfile(
        &tls_config,
        tls_port,
        &leaf_cert,
        &leaf_key,
        hub_listener,
        &artifact_root,
    );
    let sshd_key_line = ssh.sshd_host_public.trim();
    let operator_public = public_key(&ssh.operator);
    let reverse_port = free_port();
    let config_path = hub_config(
        root,
        hub_listener,
        &tls_url,
        ssh.ssh_port,
        reverse_port,
        sshd_key_line,
        &operator_public,
    );
    let operator_token = format!("fixture-operator-{}", uuid::Uuid::new_v4().simple());
    let gateway_token = format!("fixture-gateway-{}", uuid::Uuid::new_v4().simple());
    let mut hub = Command::new(hub_bin);
    hub.args(["serve", "--config"])
        .arg(&config_path)
        .env("HOSTLINK_HUB_OPERATOR_TOKEN", &operator_token)
        .env("HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN", &gateway_token)
        .stdout(private_log(&root.join("hub.stdout.log")))
        .stderr(private_log(&root.join("hub.stderr.log")));
    let hub_child = children.start(hub);
    wait_port(hub_listener, Some(hub_child));
    let caddy_bin =
        std::env::var_os("HOSTLINK_CADDY_BIN").unwrap_or_else(|| "/usr/bin/caddy".into());
    let mut caddy = Command::new(caddy_bin);
    private_dir(&root.join("caddy-home"));
    private_dir(&root.join("caddy-config"));
    private_dir(&root.join("caddy-data"));
    caddy
        .args(["run", "--config"])
        .arg(&tls_config)
        .args(["--adapter", "caddyfile"])
        .env("HOME", root.join("caddy-home"))
        .env("XDG_CONFIG_HOME", root.join("caddy-config"))
        .env("XDG_DATA_HOME", root.join("caddy-data"))
        .stdout(private_log(&root.join("caddy.stdout.log")))
        .stderr(private_log(&root.join("caddy.stderr.log")));
    let caddy_child = children.start(caddy);
    wait_port(
        SocketAddr::from(([127, 0, 0, 1], tls_port)),
        Some(caddy_child),
    );

    let token_file = root.join("operator.token");
    private_write(&token_file, operator_token);
    let controller_config = HubConfig {
        hub_url: tls_url.clone(),
        hub_ca_cert: Some(ca_cert.clone()),
        token_file: token_file.clone(),
        ssh_user: std::env::var("USER").unwrap(),
        identity: ssh.controller_key.clone(),
        gateway_identity: ssh.controller_key.clone(),
        preferred_gateway: None,
    };
    let cli_config = root.join("controller-hub.json");
    let mut configure = Command::new(client_bin);
    cli_env(&mut configure, &cli_config);
    run_ok(
        configure
            .args(["hub", "configure", "--hub-url", &tls_url, "--hub-ca-cert"])
            .arg(&ca_cert)
            .args(["--token-file"])
            .arg(&token_file)
            .args(["--ssh-user"])
            .arg(std::env::var("USER").unwrap())
            .args(["--identity"])
            .arg(&ssh.controller_key)
            .args(["--gateway-identity"])
            .arg(&ssh.controller_key),
        "actual Hub controller configuration command",
    );
    let hub_client =
        HubClient::from_config(&controller_config).expect("valid HTTPS with explicit local CA");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if hub_client.list_hosts().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("trusted HTTPS endpoint and child Hub become ready");

    HubFixture {
        tls_port,
        tls_url,
        ca_cert,
        artifact_root,
        controller_config,
        cli_config,
        hub_client,
    }
}
