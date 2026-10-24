//! Async supervisor adapter for the embedded target russh server.

use super::*;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Owned embedded-server lifecycle running on the resident tunnel supervisor runtime.
pub(super) struct EmbeddedSshServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl EmbeddedSshServerHandle {
    pub(super) async fn start(config: &EmbeddedSshServerConfig) -> io::Result<Self> {
        if config.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "embedded_ssh_server.port must be non-zero",
            ));
        }
        let prepared = config.runtime_config().prepare()?;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.port)).await?;
        Self::start_prepared(config.port, listener, prepared).await
    }

    #[cfg(test)]
    pub(super) async fn start_with_listener(
        config: &EmbeddedSshServerConfig,
        listener: tokio::net::TcpListener,
    ) -> io::Result<Self> {
        let prepared = config.runtime_config().prepare()?;
        Self::start_prepared(config.port, listener, prepared).await
    }

    async fn start_prepared(
        configured_port: u16,
        listener: tokio::net::TcpListener,
        prepared: crate::embedded_ssh::PreparedEmbeddedSshConfig,
    ) -> io::Result<Self> {
        let address = listener.local_addr()?;
        if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() != configured_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "embedded SSH listener must be bound to its configured IPv4 loopback port",
            ));
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(crate::embedded_ssh::serve_prepared_until(
            listener,
            prepared,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        tokio::task::yield_now().await;
        if task.is_finished() {
            return match task.await {
                Ok(Ok(())) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "embedded SSH server exited before readiness",
                )),
                Ok(Err(error)) => Err(error),
                Err(error) => Err(io::Error::other(format!(
                    "embedded SSH server task failed before readiness: {error}"
                ))),
            };
        }

        Ok(Self {
            shutdown: Some(shutdown_tx),
            task: Some(task),
        })
    }

    pub(super) async fn try_wait(&mut self) -> io::Result<Option<()>> {
        let Some(task) = self.task.as_ref() else {
            return Ok(Some(()));
        };
        if !task.is_finished() {
            return Ok(None);
        }
        self.join().await.map(Some)
    }

    pub(super) async fn terminate(&mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.join().await
    }

    async fn join(&mut self) -> io::Result<()> {
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(format!(
                "embedded SSH server task failed: {error}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embedded_server_handle_uses_current_runtime_and_terminates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("host key");
        let client_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .expect("client key");
        let host_key_path = dir.path().join("ssh_host_ed25519_key");
        let authorized_keys_path = dir.path().join("sshd_authorized_keys");
        fs::write(
            &host_key_path,
            host_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .expect("host encoding"),
        )
        .expect("host key file");
        onec_core::restrict_private_file(&host_key_path).expect("private host key");
        fs::write(
            &authorized_keys_path,
            client_key
                .public_key()
                .to_openssh()
                .expect("client public key"),
        )
        .expect("authorized keys");

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
            listener.local_addr().expect("reserved address").port()
        };
        let config = EmbeddedSshServerConfig {
            user: "managed-user".to_owned(),
            host_key: host_key_path,
            authorized_keys: authorized_keys_path,
            port,
        };

        let mut handle = EmbeddedSshServerHandle::start(&config)
            .await
            .expect("embedded server start");
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("embedded listener live");
        handle.terminate().await.expect("embedded server terminate");
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err(),
            "listener must close after owned termination"
        );
    }
}
