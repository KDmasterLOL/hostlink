//! Binary standard SSH exec, outputs, and exit status.

use russh::{ChannelMsg, ChannelWriteHalf, client::Msg};
use std::time::Duration;

use crate::connect::{HostConnection, MAX_TRANSFER_BYTES, OPERATION_TIMEOUT, SshClientError};

/// Raw result from one SSH exec request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exact SSH exit-status value.
    pub exit_code: u32,
}

const EXEC_STDIN_CHUNK_BYTES: usize = 32 * 1024;
const EXEC_CHANNEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

impl HostConnection {
    /// Runs one UTF-8 SSH command string and sends raw binary standard input.
    ///
    /// The SSH protocol sends a shell command string; this method does not
    /// accept or synthesize an argv vector. Output and total duration are bounded.
    ///
    /// # Errors
    /// Returns an error for invalid commands, transport errors, missing status,
    /// timeout, or output exceeding the transfer limit.
    pub async fn exec(
        &mut self,
        command: &str,
        input: &[u8],
    ) -> Result<ExecOutput, SshClientError> {
        validate_command(command)?;
        if input.len() > MAX_TRANSFER_BYTES {
            return Err(SshClientError::TransferTooLarge);
        }
        self.exec_inner(command, input).await
    }

    async fn exec_inner(
        &mut self,
        command: &str,
        input: &[u8],
    ) -> Result<ExecOutput, SshClientError> {
        let deadline = tokio::time::Instant::now() + OPERATION_TIMEOUT;
        let channel = tokio::time::timeout_at(deadline, self.session.channel_open_session())
            .await
            .map_err(|_| SshClientError::Timeout)??;
        let (mut reader, writer) = channel.split();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;
        let mut remote_closed = false;

        match tokio::time::timeout_at(deadline, writer.exec(true, command.as_bytes())).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                close_channel(&writer).await;
                return Err(error.into());
            }
            Err(_) => {
                close_channel(&writer).await;
                return Err(SshClientError::Timeout);
            }
        }

        for chunk in input.chunks(EXEC_STDIN_CHUNK_BYTES) {
            let send = writer.data_bytes(chunk.to_vec());
            tokio::pin!(send);
            let send_result = loop {
                tokio::select! {
                    result = &mut send => break Some(result),
                    message = reader.wait() => {
                        if let Err(error) = record_message(message, &mut stdout, &mut stderr, &mut exit_code, &mut remote_closed) {
                            if !remote_closed { close_channel(&writer).await; }
                            return Err(error);
                        }
                        if remote_closed {
                            return Err(SshClientError::EarlyChannelClose);
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => break None,
                }
            };
            match send_result {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    close_channel(&writer).await;
                    return Err(error.into());
                }
                None => {
                    close_channel(&writer).await;
                    return Err(SshClientError::Timeout);
                }
            }
        }

        let eof = tokio::time::timeout_at(deadline, writer.eof()).await;
        match eof {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                close_channel(&writer).await;
                return Err(error.into());
            }
            Err(_) => {
                close_channel(&writer).await;
                return Err(SshClientError::Timeout);
            }
        }

        while !remote_closed {
            tokio::select! {
                message = reader.wait() => {
                    if let Err(error) = record_message(message, &mut stdout, &mut stderr, &mut exit_code, &mut remote_closed) {
                        if !remote_closed { close_channel(&writer).await; }
                        return Err(error);
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    close_channel(&writer).await;
                    return Err(SshClientError::Timeout);
                }
            }
        }
        let exit_code = exit_code.ok_or(SshClientError::MissingExitStatus)?;
        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code,
        })
    }
}

async fn close_channel(channel: &ChannelWriteHalf<Msg>) {
    let _ = tokio::time::timeout(EXEC_CHANNEL_CLEANUP_TIMEOUT, channel.close()).await;
}

fn record_message(
    message: Option<ChannelMsg>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    exit_code: &mut Option<u32>,
    remote_closed: &mut bool,
) -> Result<(), SshClientError> {
    match message {
        Some(ChannelMsg::Data { data }) => append_bounded(stdout, stderr, &data, false)?,
        Some(ChannelMsg::ExtendedData { ext: 1, data }) => {
            append_bounded(stdout, stderr, &data, true)?
        }
        Some(ChannelMsg::ExtendedData { ext, .. }) => {
            return Err(SshClientError::Invalid(format!(
                "unsupported SSH extended-data type {ext}"
            )));
        }
        Some(ChannelMsg::ExitStatus { exit_status }) => {
            if exit_code.replace(exit_status).is_some() {
                return Err(SshClientError::Invalid("duplicate SSH exit status".into()));
            }
        }
        Some(ChannelMsg::Close) | None => *remote_closed = true,
        Some(ChannelMsg::Eof | ChannelMsg::WindowAdjusted { .. }) => {}
        Some(_) => {}
    }
    Ok(())
}

fn append_bounded(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    data: &[u8],
    is_stderr: bool,
) -> Result<(), SshClientError> {
    if stdout
        .len()
        .saturating_add(stderr.len())
        .saturating_add(data.len())
        > MAX_TRANSFER_BYTES
    {
        return Err(SshClientError::TransferTooLarge);
    }
    if is_stderr {
        stderr.extend_from_slice(data);
    } else {
        stdout.extend_from_slice(data);
    }
    Ok(())
}

fn validate_command(command: &str) -> Result<(), SshClientError> {
    if command.is_empty() || command.as_bytes().contains(&0) {
        return Err(SshClientError::Invalid(
            "SSH command must be nonempty UTF-8 without NUL".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
    }

    struct EchoHandler {
        authorized_key: PublicKey,
        behavior: ServerBehavior,
    }

    impl server::Handler for EchoHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            key: &PublicKey,
        ) -> Result<Auth, Self::Error> {
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
            if matches!(self.behavior, ServerBehavior::CloseWithoutStatus) {
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
    async fn rejects_wrong_pinned_host_key() {
        let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("generate fixture client key");
        let wrong_host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("generate wrong host key");
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
}
