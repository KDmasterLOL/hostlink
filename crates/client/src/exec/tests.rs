use super::*;
use russh::{
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{self, Auth, Msg, Session},
};
use std::sync::Arc;
use tokio::{io::DuplexStream, task::JoinHandle};

#[test]
fn rejects_empty_and_nul_commands() {
    assert!(matches!(
        validate_command(""),
        Err(SshClientError::Invalid(_))
    ));
    assert!(matches!(
        validate_command("echo\0x"),
        Err(SshClientError::Invalid(_))
    ));
    assert!(validate_command("printf 'ok'\n").is_ok());
}

#[derive(Clone, Copy)]
enum ServerBehavior {
    Echo,
    BinaryOutput,
    CloseWithoutStatus,
    CloseDuringInput,
    SlowExecRequest,
}

struct EchoHandler {
    authorized_key: PublicKey,
    behavior: ServerBehavior,
}

impl server::Handler for EchoHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(if key == &self.authorized_key {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if matches!(self.behavior, ServerBehavior::SlowExecRequest) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else if matches!(self.behavior, ServerBehavior::CloseWithoutStatus) {
            session.close(channel)?;
        } else if matches!(self.behavior, ServerBehavior::BinaryOutput) {
            session.data(channel, vec![0, 255, 10])?;
            session.extended_data(channel, 1, vec![255, 0, 13])?;
            session.exit_status_request(channel, 7)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.behavior, ServerBehavior::Echo) {
            session.data(channel, data.to_vec())?;
        } else if matches!(self.behavior, ServerBehavior::CloseDuringInput) {
            session.close(channel)?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.behavior, ServerBehavior::Echo) {
            session.eof(channel)?;
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

async fn spawn_server(
    client_stream: DuplexStream,
    server_stream: DuplexStream,
    client_identity: &PrivateKey,
    behavior: ServerBehavior,
) -> (
    DuplexStream,
    JoinHandle<Result<(), russh::Error>>,
    PublicKey,
) {
    let server_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate fixture server key");
    let host_pin = server_key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![server_key],
        ..Default::default()
    });
    let handler = EchoHandler {
        authorized_key: client_identity.public_key().clone(),
        behavior,
    };
    let task = tokio::spawn(async move {
        let session = server::run_stream(config, server_stream, handler).await?;
        session.await
    });
    (client_stream, task, host_pin)
}

async fn duplex_pair() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(256 * 1024)
}

async fn authenticated_pair(
    behavior: ServerBehavior,
) -> (
    HostConnection,
    JoinHandle<Result<(), russh::Error>>,
    PrivateKey,
    PublicKey,
) {
    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate fixture client key");
    let (client_stream, server_stream) = duplex_pair().await;
    let (client_stream, server_task, host_pin) =
        spawn_server(client_stream, server_stream, &identity, behavior).await;
    let session = crate::connect::connect_stream_authenticated(
        client_stream,
        "fixture-user",
        identity.clone(),
        host_pin.clone(),
    )
    .await
    .expect("authenticate fixture client");
    (
        HostConnection::from_authenticated_session(session),
        server_task,
        identity,
        host_pin,
    )
}

#[tokio::test]
async fn stdin_larger_than_ssh_window_echoes_while_uploading() {
    let (mut connection, server_task, _, _) = authenticated_pair(ServerBehavior::Echo).await;
    let input: Vec<u8> = (0_usize..(4 * 1024 * 1024 + 17))
        .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
        .collect();
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        connection.exec("fixture-echo", &input),
    )
    .await
    .expect("large bidirectional echo must not deadlock")
    .expect("exec must succeed");
    assert_eq!(output.stdout, input);
    assert!(output.stderr.is_empty());
    assert_eq!(output.exit_code, 0);
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");
}

#[tokio::test]
async fn server_close_without_status_is_an_error() {
    let (mut connection, server_task, _, _) =
        authenticated_pair(ServerBehavior::CloseWithoutStatus).await;
    let result = connection.exec("fixture-close", &[]).await;
    assert!(matches!(result, Err(SshClientError::MissingExitStatus)));
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");
}

#[tokio::test]
async fn early_channel_close_during_stdin_is_an_error() {
    let (mut connection, server_task, _, _) =
        authenticated_pair(ServerBehavior::CloseDuringInput).await;
    let input = vec![0x5a; 4 * 1024 * 1024];
    let result = connection.exec("fixture-early-close", &input).await;
    assert!(matches!(result, Err(SshClientError::EarlyChannelClose)));
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");
}

#[tokio::test]
async fn exec_preserves_binary_stdout_stderr_and_nonzero_status() {
    let (mut connection, server_task, _, _) =
        authenticated_pair(ServerBehavior::BinaryOutput).await;
    let output = connection
        .exec("fixture-output", &[])
        .await
        .expect("exec response");
    assert_eq!(output.stdout, [0, 255, 10]);
    assert_eq!(output.stderr, [255, 0, 13]);
    assert_eq!(output.exit_code, 7);
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");
}

#[tokio::test]
async fn exec_with_timeout_accepts_supported_bounds_and_times_out_slow_server() {
    let (mut connection, server_task, _, _) = authenticated_pair(ServerBehavior::Echo).await;
    for seconds in [1, 300, 600] {
        let output = connection
            .exec_with_timeout("fixture-timeout-range", b"ok", Duration::from_secs(seconds))
            .await
            .expect("supported timeout should run command");
        assert_eq!(output.stdout, b"ok");
        assert_eq!(output.exit_code, 0);
    }
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");

    let (mut connection, server_task, _, _) =
        authenticated_pair(ServerBehavior::SlowExecRequest).await;
    let result = connection
        .exec_with_timeout("fixture-slow", b"single attempt", Duration::from_secs(1))
        .await;
    assert!(matches!(result, Err(SshClientError::Timeout)));
    connection.close().await.expect("close SSH session");
    let server_result = server_task.await.expect("join fixture server");
    assert!(matches!(
        server_result,
        Err(russh::Error::IO(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
}

#[tokio::test]
async fn exec_with_timeout_rejects_values_outside_cli_bounds() {
    let (mut connection, server_task, _, _) = authenticated_pair(ServerBehavior::Echo).await;
    for timeout in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(601),
    ] {
        assert!(matches!(
            connection
                .exec_with_timeout("fixture-invalid-timeout", &[], timeout)
                .await,
            Err(SshClientError::Invalid(_))
        ));
    }
    connection.close().await.expect("close SSH session");
    server_task
        .await
        .expect("join fixture server")
        .expect("server stopped");
}

#[tokio::test]
async fn rejects_wrong_pinned_host_key() {
    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate fixture client key");
    let wrong_host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("generate wrong host key");
    let (client_stream, server_stream) = duplex_pair().await;
    let (client_stream, server_task, actual_pin) = spawn_server(
        client_stream,
        server_stream,
        &identity,
        ServerBehavior::Echo,
    )
    .await;
    let result = crate::connect::connect_stream_authenticated(
        client_stream,
        "fixture-user",
        identity,
        wrong_host_key.public_key().clone(),
    )
    .await;
    assert!(result.is_err());
    assert_ne!(actual_pin, wrong_host_key.public_key().clone());
    let _ = server_task.await;
}

#[tokio::test]
async fn rejects_wrong_authentication_identity() {
    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate fixture authorized key");
    let wrong_identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .expect("generate fixture wrong key");
    let (client_stream, server_stream) = duplex_pair().await;
    let (client_stream, server_task, host_pin) = spawn_server(
        client_stream,
        server_stream,
        &identity,
        ServerBehavior::Echo,
    )
    .await;
    let result = crate::connect::connect_stream_authenticated(
        client_stream,
        "fixture-user",
        wrong_identity,
        host_pin,
    )
    .await;
    assert!(result.is_err());
    let _ = server_task.await;
}
