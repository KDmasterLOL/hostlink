//! Agent tunnel supervision, reconnect policy, shutdown, and connectivity probing.

use super::*;
use crate::environment::AgentEnvironmentPolicy;
use tokio::task::JoinSet;

const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(100);

enum TargetSshServer {
    External(TunnelChild),
    Embedded(EmbeddedSshServerHandle),
}

impl TargetSshServer {
    async fn start(
        config: &AgentConfig,
        environment: &AgentEnvironmentPolicy,
    ) -> io::Result<Option<Self>> {
        if let Some(server) = config.ssh_server() {
            let mut child = spawn_ssh_server(server, environment)?;
            wait_for_ssh_server(server, &mut child).await?;
            agent_event(
                "user_sshd.ready",
                "info",
                AgentEventFields::default().listen_port(server.port),
            );
            return Ok(Some(Self::External(child)));
        }
        if let Some(server) = config.embedded_ssh_server() {
            let embedded = EmbeddedSshServerHandle::start(server).await?;
            agent_event(
                "embedded_ssh.ready",
                "info",
                AgentEventFields::default().listen_port(server.port),
            );
            return Ok(Some(Self::Embedded(embedded)));
        }
        Ok(None)
    }

    async fn try_wait(&mut self) -> io::Result<Option<String>> {
        match self {
            Self::External(child) => Ok(child
                .try_wait()?
                .map(|status| format!("user-mode sshd exited with {status}"))),
            Self::Embedded(server) => Ok(server
                .try_wait()
                .await?
                .map(|()| "embedded SSH server exited unexpectedly".to_owned())),
        }
    }

    async fn terminate(&mut self) -> io::Result<()> {
        match self {
            Self::External(child) => child.terminate(),
            Self::Embedded(server) => server.terminate().await,
        }
    }
}

enum MonitorOutcome {
    Shutdown,
    TargetExited(String),
}

/// Runs the control listener plus managed target SSH server/reverse tunnel with reconnect supervision.
///
/// The synchronous API owns exactly one Tokio runtime for the resident async tunnel lifecycle.
/// Tunnel exits are retried according to configuration. Loss of the optional target SSH server is
/// fatal so the outer service supervisor can restart the complete agent.
///
/// # Errors
///
/// Returns an I/O error when configuration, listener, target-server or tunnel prerequisites fail,
/// or when a fatal supervised-server condition occurs.
pub fn run_with_tunnel(config: &AgentConfig) -> io::Result<()> {
    let shutdown = AtomicBool::new(false);
    run_with_tunnel_until(config, &shutdown)
}

pub(crate) fn run_with_tunnel_until(config: &AgentConfig, shutdown: &AtomicBool) -> io::Result<()> {
    tunnel_runtime()?.block_on(run_with_tunnel_until_async(config, shutdown))
}

async fn run_with_tunnel_until_async(
    config: &AgentConfig,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let ssh = config.ssh().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "run mode requires an ssh section in the agent config",
        )
    })?;
    agent_event(
        "agent.run.started",
        "info",
        AgentEventFields::default().remote_port(ssh.remote_port),
    );

    let listen = config.listen();
    let runtime = config.runtime()?;
    let environment = AgentEnvironmentPolicy::new(config.secret_env());
    let control_environment = environment.clone();
    let listener = TcpListener::bind(listen)?;
    let control_runtime = tokio::runtime::Handle::current();
    agent_event(
        "control.listener.ready",
        "info",
        AgentEventFields::default().listen_port(listen.port()),
    );
    thread::spawn(move || {
        if let Err(error) = serve_listener(listener, runtime, control_environment, control_runtime)
        {
            agent_event(
                "control.listener.failed",
                "error",
                AgentEventFields::default(),
            );
            eprintln!("onec-agent control server stopped: {error}");
            std::process::exit(2);
        }
    });

    let mut ssh_server = TargetSshServer::start(config, &environment).await?;
    let local_target_port = config.ssh_target_port();
    supervise_reverse_tunnel(
        &ssh,
        local_target_port,
        &environment,
        &mut ssh_server,
        shutdown,
    )
    .await
}

async fn supervise_reverse_tunnel(
    ssh: &SshTunnelConfig,
    local_target_port: u16,
    environment: &AgentEnvironmentPolicy,
    ssh_server: &mut Option<TargetSshServer>,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    if ssh.gateways.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run mode requires at least one approved gateway",
        ));
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut edges = JoinSet::new();
    for gateway in ssh.gateways.iter().cloned() {
        let config = ssh.clone();
        let edge_environment = environment.clone();
        let edge_shutdown = shutdown_rx.clone();
        edges.spawn(async move {
            supervise_gateway(
                config,
                gateway,
                local_target_port,
                edge_environment,
                edge_shutdown,
            )
            .await
        });
    }

    let outcome = monitor_target_or_shutdown(ssh_server, shutdown).await;
    let _ = shutdown_tx.send(true);
    let cleanup = tokio::time::timeout(Duration::from_secs(15), async {
        while edges.join_next().await.is_some() {}
    })
    .await;
    if cleanup.is_err() {
        edges.abort_all();
        while edges.join_next().await.is_some() {}
    }
    terminate_target_server(ssh_server).await;

    match outcome? {
        MonitorOutcome::Shutdown => {
            agent_event("agent.run.stopped", "info", AgentEventFields::default());
            Ok(())
        }
        MonitorOutcome::TargetExited(detail) => target_server_exit(detail),
    }
}

async fn supervise_gateway(
    config: SshTunnelConfig,
    gateway: SshGatewayEndpoint,
    local_target_port: u16,
    environment: AgentEnvironmentPolicy,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let connect = ReverseTunnel::connect(&config, &gateway, local_target_port, &environment);
        let connected = tokio::select! {
            result = connect => result,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
                continue;
            }
        };
        let mut tunnel = match connected {
            Ok(tunnel) => {
                agent_event(
                    "tunnel.started",
                    "info",
                    AgentEventFields::default()
                        .remote_port(config.remote_port)
                        .local_port(local_target_port),
                );
                tunnel
            }
            Err(error) => {
                eprintln!(
                    "onec-agent failed to establish SSH tunnel to {}:{}: {error}; reconnecting in {}s",
                    gateway.host, gateway.port, config.reconnect_seconds
                );
                if wait_edge_reconnect(&mut shutdown, config.reconnect_seconds).await {
                    return;
                }
                continue;
            }
        };

        let ended = tokio::select! {
            result = tunnel.wait() => Some(result),
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = tunnel.shutdown().await;
                    return;
                }
                None
            }
        };
        if let Some(result) = ended {
            agent_event("tunnel.exited", "warn", AgentEventFields::default());
            if let Err(error) = result {
                eprintln!(
                    "onec-agent SSH tunnel to {}:{} ended: {error}",
                    gateway.host, gateway.port
                );
            }
        }
        if wait_edge_reconnect(&mut shutdown, config.reconnect_seconds).await {
            return;
        }
    }
}

async fn wait_edge_reconnect(
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    reconnect_seconds: u64,
) -> bool {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(reconnect_seconds.max(1))) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

async fn monitor_target_or_shutdown(
    server: &mut Option<TargetSshServer>,
    shutdown: &AtomicBool,
) -> io::Result<MonitorOutcome> {
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(MonitorOutcome::Shutdown);
        }
        if let Some(server) = server.as_mut()
            && let Some(detail) = server.try_wait().await?
        {
            agent_event(
                "target_ssh_server.exited",
                "error",
                AgentEventFields::default(),
            );
            return Ok(MonitorOutcome::TargetExited(detail));
        }
        tokio::time::sleep(SUPERVISOR_POLL_INTERVAL).await;
    }
}

async fn monitor_target(server: &mut Option<TargetSshServer>) -> io::Result<String> {
    loop {
        if let Some(server) = server.as_mut()
            && let Some(detail) = server.try_wait().await?
        {
            return Ok(detail);
        }
        tokio::time::sleep(SUPERVISOR_POLL_INTERVAL).await;
    }
}

async fn terminate_target_server(server: &mut Option<TargetSshServer>) {
    if let Some(server) = server.as_mut() {
        let _ = server.terminate().await;
    }
}

fn target_server_exit(detail: String) -> io::Result<()> {
    Err(io::Error::other(format!(
        "{detail}; supervisor will restart onec-agent"
    )))
}

/// Starts the configured target server/tunnel pair and proves they remain alive for hold_for.
///
/// This is a bounded connectivity/readiness probe rather than the reconnecting service loop.
///
/// # Errors
///
/// Returns an I/O error when prerequisites/startup fail or either endpoint exits during the
/// requested hold interval.
pub fn probe_tunnel(config: &AgentConfig, hold_for: Duration) -> io::Result<()> {
    tunnel_runtime()?.block_on(probe_tunnel_async(config, hold_for))
}

async fn probe_tunnel_async(config: &AgentConfig, hold_for: Duration) -> io::Result<()> {
    let ssh = config.ssh().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe-tunnel requires an ssh section in the agent config",
        )
    })?;
    let environment = AgentEnvironmentPolicy::new(config.secret_env());
    let mut ssh_server = TargetSshServer::start(config, &environment).await?;
    let local_target_port = config.ssh_target_port();
    let mut diagnostics = Vec::new();
    let probe_started = tokio::time::Instant::now();
    for gateway in &ssh.gateways {
        enum ConnectOutcome {
            Tunnel(Box<io::Result<ReverseTunnel>>),
            Target(io::Result<String>),
        }
        let outcome = {
            let connection = ReverseTunnel::connect(ssh, gateway, local_target_port, &environment);
            let target = monitor_target(&mut ssh_server);
            tokio::pin!(connection);
            tokio::pin!(target);
            tokio::select! {
                result = &mut connection => ConnectOutcome::Tunnel(Box::new(result)),
                result = &mut target => ConnectOutcome::Target(result),
            }
        };
        let connected = match outcome {
            ConnectOutcome::Tunnel(result) => *result,
            ConnectOutcome::Target(result) => {
                terminate_target_server(&mut ssh_server).await;
                let detail = result.unwrap_or_else(|error| error.to_string());
                return Err(io::Error::other(format!(
                    "target SSH server exited during connectivity probe: {detail}"
                )));
            }
        };
        let mut tunnel = match connected {
            Ok(tunnel) => tunnel,
            Err(error) => {
                diagnostics.push(format!(
                    "{}:{} ({:?})",
                    gateway.host,
                    gateway.port,
                    error.kind()
                ));
                continue;
            }
        };
        let remaining = hold_for.saturating_sub(probe_started.elapsed());
        enum HoldOutcome {
            Complete,
            Tunnel(io::Result<()>),
            Target(io::Result<String>),
        }
        let outcome = {
            let hold = tokio::time::sleep(remaining);
            tokio::pin!(hold);
            let wait = tunnel.wait();
            tokio::pin!(wait);
            let target = monitor_target(&mut ssh_server);
            tokio::pin!(target);
            tokio::select! {
                () = &mut hold => HoldOutcome::Complete,
                result = &mut wait => HoldOutcome::Tunnel(result),
                result = &mut target => HoldOutcome::Target(result),
            }
        };
        match outcome {
            HoldOutcome::Complete => {
                let tunnel_result = tunnel.shutdown().await;
                terminate_target_server(&mut ssh_server).await;
                return tunnel_result;
            }
            HoldOutcome::Target(result) => {
                let _ = tunnel.shutdown().await;
                terminate_target_server(&mut ssh_server).await;
                let detail = result.unwrap_or_else(|error| error.to_string());
                return Err(io::Error::other(format!(
                    "target SSH server exited during connectivity probe: {detail}"
                )));
            }
            HoldOutcome::Tunnel(result) => {
                let _ = tunnel.shutdown().await;
                let kind = result.err().map(|error| error.kind());
                diagnostics.push(format!("{}:{} ({kind:?})", gateway.host, gateway.port));
            }
        }
    }
    terminate_target_server(&mut ssh_server).await;
    Err(io::Error::other(format!(
        "no approved SSH gateway passed the connectivity probe: {}",
        diagnostics.join(", ")
    )))
}

fn tunnel_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::super::client::tests::{active_active_fixture, reconnect_fixture, stable_fixture};
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn wait_for_attempts(attempts: &std::sync::atomic::AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while attempts.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reverse-tunnel attempt count");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervisor_reconnects_after_transient_disconnect_and_owns_shutdown() {
        let (fixture, mut ssh, attempts) = reconnect_fixture().await;
        ssh.reconnect_seconds = 1;
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&shutdown);
        tokio::task::LocalSet::new()
            .run_until(async move {
                let environment = AgentEnvironmentPolicy::default();
                let mut target_server = None;
                let task = tokio::task::spawn_local(async move {
                    supervise_reverse_tunnel(
                        &ssh,
                        27_391,
                        &environment,
                        &mut target_server,
                        signal.as_ref(),
                    )
                    .await
                });

                wait_for_attempts(&attempts, 2).await;
                shutdown.store(true, Ordering::Release);
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("supervisor shutdown deadline")
                    .expect("supervisor task")
                    .expect("supervisor result");
            })
            .await;
        fixture.abort_server();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervisor_shutdown_interrupts_reconnect_backoff() {
        let (fixture, mut ssh, attempts) = reconnect_fixture().await;
        ssh.reconnect_seconds = 5;
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&shutdown);
        tokio::task::LocalSet::new()
            .run_until(async move {
                let environment = AgentEnvironmentPolicy::default();
                let mut target_server = None;
                let task = tokio::task::spawn_local(async move {
                    supervise_reverse_tunnel(
                        &ssh,
                        27_391,
                        &environment,
                        &mut target_server,
                        signal.as_ref(),
                    )
                    .await
                });

                wait_for_attempts(&attempts, 1).await;
                tokio::time::sleep(Duration::from_millis(250)).await;
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    1,
                    "supervisor must still be in the configured reconnect backoff"
                );
                shutdown.store(true, Ordering::Release);
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .expect("shutdown must interrupt reconnect backoff")
                    .expect("supervisor task")
                    .expect("supervisor result");
            })
            .await;
        fixture.abort_server();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unavailable_gateway_does_not_interrupt_healthy_edge_and_shutdown_joins_all() {
        let (first, second, mut ssh) = active_active_fixture().await;
        ssh.gateways[0].port = 1;
        let local = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local target listener");
        let local_port = local.local_addr().expect("local target address").port();
        let target = tokio::spawn(async move {
            let (mut stream, _) = local.accept().await.expect("target accept");
            let mut bytes = [0_u8; 16];
            let read = stream.read(&mut bytes).await.expect("target read");
            stream.write_all(&bytes[..read]).await.expect("target echo");
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&shutdown);
        let remote_port = ssh.remote_port;
        let local_set = tokio::task::LocalSet::new();
        let task = local_set.run_until(async {
            let environment = AgentEnvironmentPolicy::default();
            let mut target_server = None;
            let task = tokio::task::spawn_local(async move {
                supervise_reverse_tunnel(
                    &ssh,
                    local_port,
                    &environment,
                    &mut target_server,
                    signal.as_ref(),
                )
                .await
            });
            second.wait_forward_requested().await;
            let mut remote = tokio::net::TcpStream::connect(("127.0.0.3", remote_port))
                .await
                .expect("healthy gateway reverse listener");
            remote
                .write_all(b"edge-isolated")
                .await
                .expect("remote write");
            let mut echoed = [0; 13];
            remote.read_exact(&mut echoed).await.expect("remote echo");
            assert_eq!(&echoed, b"edge-isolated");
            assert!(!task.is_finished(), "failed edge must not end supervisor");

            shutdown.store(true, Ordering::Release);
            tokio::time::timeout(Duration::from_secs(16), task)
                .await
                .expect("supervisor must shut down every owned edge tunnel")
                .expect("supervisor task")
                .expect("supervisor result");
        });
        task.await;
        target.await.expect("target task");
        first.abort_server();
        second.abort_server();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedded_target_is_forwarded_and_closed_with_supervisor_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("embedded host key");
        let authorized_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("embedded authorized key");
        let host_key_path = dir.path().join("ssh_host_ed25519_key");
        let authorized_keys_path = dir.path().join("authorized_keys");
        fs::write(
            &host_key_path,
            host_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .expect("embedded host key encoding"),
        )
        .expect("write embedded host key");
        onec_core::restrict_private_file(&host_key_path).expect("private embedded host key");
        fs::write(
            &authorized_keys_path,
            authorized_key
                .public_key()
                .to_openssh()
                .expect("embedded authorized public key"),
        )
        .expect("write embedded authorized keys");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve embedded port");
        let embedded_port = listener.local_addr().expect("embedded address").port();

        let (fixture, ssh) = stable_fixture().await;
        let config: AgentConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "name": "embedded-reverse-forward",
            "listen": "127.0.0.1:27391",
            "ssh": &ssh,
            "embedded_ssh_server": {
                "user": "managed-user",
                "host_key": host_key_path,
                "authorized_keys": authorized_keys_path,
                "port": embedded_port
            }
        }))
        .expect("static agent config");
        let remote_port = fixture.remote_port();
        tokio::task::LocalSet::new()
            .run_until(async move {
                let environment = AgentEnvironmentPolicy::default();
                let embedded_config = config
                    .embedded_ssh_server()
                    .expect("embedded target config");
                let target_server =
                    EmbeddedSshServerHandle::start_with_listener(embedded_config, listener)
                        .await
                        .expect("embedded target start");
                let target_server = Some(TargetSshServer::Embedded(target_server));
                tokio::net::TcpStream::connect(("127.0.0.1", embedded_port))
                    .await
                    .expect("embedded listener live before supervisor");

                let shutdown = Arc::new(AtomicBool::new(false));
                let signal = Arc::clone(&shutdown);
                let local_target_port = config.ssh_target_port();
                // Keep the server owner on a local task; only Send-safe network coordination is
                // moved to the multi-thread runtime.
                let task = tokio::task::spawn_local(async move {
                    let mut target_server = target_server;
                    supervise_reverse_tunnel(
                        &ssh,
                        local_target_port,
                        &environment,
                        &mut target_server,
                        signal.as_ref(),
                    )
                    .await
                });

                let coordination_signal = Arc::clone(&shutdown);
                let coordination = tokio::spawn(async move {
                    let mut remote = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(("127.0.0.1", remote_port)),
                    )
                    .await
                    .expect("reverse listener connect deadline")
                    .expect("connect reverse listener");
                    let mut banner = [0_u8; 64];
                    let read =
                        tokio::time::timeout(Duration::from_secs(5), remote.read(&mut banner))
                            .await
                            .expect("embedded SSH banner deadline")
                            .expect("read embedded SSH banner");
                    assert!(
                        banner[..read].starts_with(b"SSH-2.0-"),
                        "reverse forward must terminate at the embedded SSH server"
                    );
                    coordination_signal.store(true, Ordering::Release);
                });
                tokio::time::timeout(Duration::from_secs(11), coordination)
                    .await
                    .expect("network coordination deadline")
                    .expect("network coordination task");
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("supervisor shutdown deadline")
                    .expect("supervisor task")
                    .expect("supervisor result");

                assert!(
                    tokio::net::TcpStream::connect(("127.0.0.1", embedded_port))
                        .await
                        .is_err(),
                    "embedded listener must be closed before supervisor shutdown returns"
                );
            })
            .await;
        fixture.abort_server();
    }

    #[test]
    fn reverse_tunnel_supervisor_has_one_runtime_boundary_and_no_blocking_sleep() {
        let supervisor = include_str!("supervisor.rs");
        let embedded = include_str!("embedded_server.rs");
        let supervisor_runtime = supervisor
            .split("#[cfg(test)]")
            .next()
            .expect("production supervisor source");
        let embedded_runtime = embedded
            .split("#[cfg(test)]")
            .next()
            .expect("production embedded-server source");

        assert_eq!(
            supervisor_runtime
                .matches("tokio::runtime::Builder")
                .count(),
            1,
            "sync Run/Probe/Service boundary must share one runtime constructor"
        );
        assert!(!supervisor_runtime.contains("thread::sleep"));
        assert!(!embedded_runtime.contains("tokio::runtime::Builder"));
        assert!(!embedded_runtime.contains("block_on("));
        assert!(!embedded_runtime.contains("thread::Builder"));
    }
}
