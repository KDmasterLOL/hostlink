use super::*;

struct GatewayHandler {
    host_key: russh::keys::PublicKey,
    remote_port: u16,
    forwards: mpsc::Sender<(Channel<Msg>, ChannelOpenHandle)>,
}

impl client::Handler for GatewayHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(presented.certificate().is_none()
            && presented.public_key().algorithm() == Algorithm::Ed25519
            && presented.public_key().key_data() == self.host_key.key_data())
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        address: &str,
        port: u32,
        _origin: &str,
        _origin_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if address != "127.0.0.1" || port != u32::from(self.remote_port) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        } else if let Err(error) = self.forwards.try_send((channel, reply)) {
            let (_, reply) = error.into_inner();
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
        }
        Ok(())
    }
}

/// Runs the optional pinned reverse tunnel until shutdown, reconnecting transient failures.
pub async fn run(
    config: &AgentConfig,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    run_with_backoff(
        config,
        shutdown,
        INITIAL_RECONNECT_BACKOFF,
        MAX_RECONNECT_BACKOFF,
    )
    .await
}

pub(super) async fn run_with_backoff(
    config: &AgentConfig,
    shutdown: impl Future<Output = ()> + Send,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> io::Result<()> {
    config.validate()?;
    let Some(primary) = config.gateway.as_ref() else {
        return Ok(());
    };
    let routes: Vec<&ReverseGateway> = std::iter::once(primary)
        .chain(config.gateway_alternates.iter())
        .collect();
    // Load and validate every approved pin before opening any network connection.
    let host_keys = routes
        .iter()
        .map(|route| load_gateway_key(&route.host_public_key))
        .collect::<io::Result<Vec<_>>>()?;
    let identity = load_identity(&primary.identity)?;
    tokio::pin!(shutdown);
    let mut backoff = initial_backoff.min(max_backoff);
    let mut route_index = 0;
    let mut attempt_count = 0_u64;
    let mut jitter_rng = StdRng::from_rng(&mut rand::rng());
    loop {
        attempt_count = attempt_count.saturating_add(1);
        emit_diagnostic(format_args!(
            "hostlink-agent tunnel event=start route_index={} route_count={} attempt={}",
            route_index + 1,
            routes.len(),
            attempt_count,
        ));
        let attempt = tunnel_once(
            routes[route_index],
            &host_keys[route_index],
            identity.clone(),
            config.listen,
            &mut shutdown,
        );
        let result = attempt.await;
        let Err(failure) = result else {
            return Ok(());
        };
        let uptime_ms = failure.uptime.as_millis();
        if failure.cancelled {
            emit_diagnostic(format_args!(
                "hostlink-agent tunnel event=end route_index={} route_count={} attempt={} phase={} class=shutdown forward_accepted={} uptime_ms={} retry=stopped",
                route_index + 1,
                routes.len(),
                attempt_count,
                failure.phase.as_str(),
                failure.forward_accepted,
                uptime_ms,
            ));
            return Ok(());
        }
        if !failure.transient {
            emit_diagnostic(format_args!(
                "hostlink-agent tunnel event=end route_index={} route_count={} attempt={} phase={} class={} forward_accepted={} uptime_ms={} retry=stopped",
                route_index + 1,
                routes.len(),
                attempt_count,
                failure.phase.as_str(),
                error_class(&failure.error),
                failure.forward_accepted,
                uptime_ms,
            ));
            return Err(failure.error);
        }
        backoff = reset_backoff_after_stable_session(
            backoff,
            initial_backoff,
            max_backoff,
            failure.uptime,
        );
        let jitter_cap = jitter_cap_ms(backoff, max_backoff);
        let jitter_ms = jitter_rng.random_range(0..=jitter_cap);
        let delay = retry_delay(backoff, max_backoff, jitter_ms);
        emit_diagnostic(format_args!(
            "hostlink-agent tunnel event=end route_index={} route_count={} attempt={} phase={} class={} forward_accepted={} uptime_ms={} retry=scheduled next_delay_ms={}",
            route_index + 1,
            routes.len(),
            attempt_count,
            failure.phase.as_str(),
            error_class(&failure.error),
            failure.forward_accepted,
            uptime_ms,
            delay.as_millis(),
        ));
        route_index = (route_index + 1) % routes.len();
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(delay) => {}
        }
        backoff = backoff.saturating_mul(2).min(max_backoff);
    }
}

async fn tunnel_once(
    gateway: &ReverseGateway,
    host_key: &russh::keys::PublicKey,
    identity: PrivateKey,
    target: std::net::SocketAddr,
    shutdown: &mut std::pin::Pin<&mut (impl Future<Output = ()> + Send)>,
) -> Result<(), AttemptFailure> {
    let (tx, mut rx) = mpsc::channel(MAX_FORWARDS);
    let handler = GatewayHandler {
        host_key: host_key.clone(),
        remote_port: gateway.remote_port,
        forwards: tx,
    };
    let ssh_config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });
    let connected = tokio::select! {
        _ = shutdown.as_mut() => return Err(AttemptFailure::cancelled(AttemptPhase::ConnectHandshake, Duration::ZERO, false)),
        result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            client::connect(ssh_config, (gateway.host.as_str(), gateway.port), handler),
        ) => result,
    };
    let mut session = connected
        .map_err(|_| {
            AttemptFailure::transient(
                io::Error::new(io::ErrorKind::TimedOut, "gateway SSH connect timed out"),
                AttemptPhase::ConnectHandshake,
            )
        })?
        .map_err(|error| ssh_failure(error, AttemptPhase::ConnectHandshake))?;
    let authenticated = tokio::select! {
        _ = shutdown.as_mut() => return Err(AttemptFailure::cancelled(AttemptPhase::Authentication, Duration::ZERO, false)),
        result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            session.authenticate_publickey(
                gateway.user.clone(),
                PrivateKeyWithHashAlg::new(Arc::new(identity), None),
            ),
        ) => result,
    };
    let auth = authenticated
        .map_err(|_| {
            AttemptFailure::transient(
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "gateway SSH authentication timed out",
                ),
                AttemptPhase::Authentication,
            )
        })?
        .map_err(|error| ssh_failure(error, AttemptPhase::Authentication))?;
    if !auth.success() {
        return Err(AttemptFailure::permanent(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway rejected pinned SSH identity",
            ),
            AttemptPhase::Authentication,
        ));
    }
    let forward_result = tokio::select! {
        _ = shutdown.as_mut() => return Err(AttemptFailure::cancelled(AttemptPhase::ReverseForward, Duration::ZERO, false)),
        result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            session.tcpip_forward("127.0.0.1", u32::from(gateway.remote_port)),
        ) => result,
    };
    let forwarded = forward_result
        .map_err(|_| {
            AttemptFailure::transient(
                io::Error::new(io::ErrorKind::TimedOut, "reverse forward request timed out"),
                AttemptPhase::ReverseForward,
            )
        })?
        .map_err(|error| ssh_failure(error, AttemptPhase::ReverseForward))?;
    // RFC 4254 returns an allocated port only when the requested port is 0.
    // russh therefore returns 0 for a confirmed *fixed-port* forward. The
    // matching address and port are enforced again for each forwarded channel.
    if forwarded != 0 {
        return Err(AttemptFailure::permanent(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway did not confirm the exact requested reverse loopback port",
            ),
            AttemptPhase::ReverseForward,
        ));
    }
    let established_at = tokio::time::Instant::now();
    let slots = Arc::new(Semaphore::new(MAX_FORWARDS));
    let mut workers = tokio::task::JoinSet::new();
    let connection = async {
        loop {
            tokio::select! {
                _ = shutdown.as_mut() => return Err(AttemptFailure::cancelled(AttemptPhase::Established, established_at.elapsed(), true)),
                result = &mut session => return result.map_err(|error| ssh_failure(error, AttemptPhase::Established)),
                request = rx.recv() => {
                    let Some((channel, reply)) = request else { return Err(AttemptFailure::transient(io::Error::new(io::ErrorKind::UnexpectedEof, "gateway forward queue closed"), AttemptPhase::Established)) };
                    let Ok(permit) = slots.clone().try_acquire_owned() else { reply.reject(ChannelOpenFailure::ResourceShortage).await; continue };
                    workers.spawn(async move {
                        let _permit = permit;
                        let target = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(target)).await;
                        let Ok(Ok(mut socket)) = target else { reply.reject(ChannelOpenFailure::ConnectFailed).await; return };
                        reply.accept().await;
                        let mut ssh = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut ssh, &mut socket).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut ssh).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
                    });
                }
                Some(_) = workers.join_next(), if !workers.is_empty() => {}
            }
        }
    };
    let mut result = connection.await;
    let established_uptime = established_at.elapsed();
    if let Err(failure) = &mut result {
        failure.phase = AttemptPhase::Established;
        failure.uptime = established_uptime;
        failure.forward_accepted = true;
    }
    workers.abort_all();
    let _ = tokio::time::timeout(WORKER_JOIN_TIMEOUT, async {
        while workers.join_next().await.is_some() {}
    })
    .await;
    // An SSH gateway can close gracefully without an error. A clean remote
    // disconnect is still a lost tunnel and must retry, not stop Agent routing.
    match result {
        Err(failure) => Err(failure),
        Ok(()) => Err(AttemptFailure {
            error: io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "gateway SSH session closed",
            ),
            transient: true,
            phase: AttemptPhase::Established,
            uptime: established_uptime,
            forward_accepted: true,
            cancelled: false,
        }),
    }
}

fn load_gateway_key(path: &Path) -> io::Result<russh::keys::PublicKey> {
    crate::private_fs::validate_private_path(path, false)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway pin must be a bounded regular file",
        ));
    }
    let text = std::fs::read_to_string(path)?;
    let key = russh::keys::PublicKey::from_openssh(text.trim()).map_err(io::Error::other)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway pin must be Ed25519",
        ));
    }
    Ok(key)
}
fn load_identity(path: &Path) -> io::Result<PrivateKey> {
    crate::private_fs::validate_private_path(path, false)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway identity must be a bounded regular file",
        ));
    }
    let key = PrivateKey::from_openssh(&std::fs::read(path)?).map_err(io::Error::other)?;
    if key.is_encrypted() || key.algorithm() != Algorithm::Ed25519 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway identity must be unencrypted Ed25519",
        ));
    }
    Ok(key)
}
