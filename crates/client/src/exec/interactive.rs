use std::time::Duration;

use russh::{ChannelMsg, client::Msg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::connect::{HostConnection, SshClientError};

const INTERACTIVE_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

impl HostConnection {
    /// Starts a PTY-backed shell after both SSH requests receive explicit success replies.
    ///
    /// Input and output are streamed in bounded chunks. The caller owns local terminal
    /// mode and must provide streams that carry raw terminal bytes.
    ///
    /// # Errors
    /// Returns transport or stream errors, a rejected PTY/shell request, an early
    /// channel close, or a channel close without a remote exit status.
    pub async fn interactive<R, W>(
        &self,
        terminal_name: &str,
        columns: u16,
        rows: u16,
        stdin: &mut R,
        stdout: &mut W,
    ) -> Result<u32, SshClientError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut channel = self.session.channel_open_session().await?;
        channel
            .request_pty(
                true,
                terminal_name,
                u32::from(columns),
                u32::from(rows),
                0,
                0,
                &[],
            )
            .await?;
        await_request_reply(&mut channel, "PTY").await?;
        channel.request_shell(true).await?;
        await_request_reply(&mut channel, "shell").await?;
        stream_terminal(&mut channel, stdin, stdout).await
    }
}

async fn await_request_reply(
    channel: &mut russh::Channel<Msg>,
    request: &str,
) -> Result<(), SshClientError> {
    let reply = tokio::time::timeout(INTERACTIVE_REQUEST_TIMEOUT, channel.wait())
        .await
        .map_err(|_| SshClientError::Timeout)?;
    match reply {
        Some(ChannelMsg::Success) => Ok(()),
        Some(ChannelMsg::Failure) => Err(SshClientError::Invalid(format!(
            "remote Agent rejected the {request} request; interactive shell requires a compatible installed Agent"
        ))),
        Some(ChannelMsg::Close) | None => Err(SshClientError::EarlyChannelClose),
        Some(message) => Err(SshClientError::Invalid(format!(
            "unexpected SSH {request} reply: {message:?}"
        ))),
    }
}

async fn stream_terminal<R, W>(
    channel: &mut russh::Channel<Msg>,
    stdin: &mut R,
    stdout: &mut W,
) -> Result<u32, SshClientError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut input = [0_u8; 8192];
    let mut stdin_closed = false;
    let mut exit_status = None;

    loop {
        tokio::select! {
            result = stdin.read(&mut input), if !stdin_closed && exit_status.is_none() => {
                match result {
                    Ok(0) => {
                        stdin_closed = true;
                        channel.eof().await?;
                    }
                    Ok(length) => channel.data_bytes(input[..length].to_vec()).await?,
                    Err(error) => return Err(error.into()),
                }
            }
            message = channel.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status: status }) => {
                        exit_status = Some(status);
                        if !stdin_closed {
                            stdin_closed = true;
                            channel.eof().await?;
                        }
                    }
                    Some(ChannelMsg::Close) => {
                        return exit_status.ok_or(SshClientError::MissingExitStatus);
                    }
                    None => return Err(SshClientError::EarlyChannelClose),
                    Some(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::{
        keys::{Algorithm, PrivateKey, PublicKey},
        server::{self, Auth, Msg, Session},
    };
    use std::{io, sync::Arc};
    use tokio::{io::DuplexStream, task::JoinHandle};

    #[derive(Clone, Copy)]
    enum FixtureBehavior {
        Accept,
        EchoInput,
        CloseWithoutStatus,
        RejectPty,
        RejectShell,
    }

    struct ShellHandler {
        authorized_key: PublicKey,
        behavior: FixtureBehavior,
    }

    impl server::Handler for ShellHandler {
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

        async fn pty_request(
            &mut self,
            channel: russh::ChannelId,
            term: &str,
            columns: u32,
            rows: u32,
            pixel_width: u32,
            pixel_height: u32,
            modes: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if matches!(self.behavior, FixtureBehavior::RejectPty)
                || term != "xterm-test"
                || columns != 80
                || rows != 24
                || pixel_width != 0
                || pixel_height != 0
                || !modes.is_empty()
            {
                session.channel_failure(channel)?;
            } else {
                session.channel_success(channel)?;
            }
            Ok(())
        }

        async fn shell_request(
            &mut self,
            channel: russh::ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if matches!(self.behavior, FixtureBehavior::RejectShell) {
                session.channel_failure(channel)?;
            } else {
                session.channel_success(channel)?;
                session.data(channel, b"fixture-shell\r\n".to_vec())?;
                if matches!(self.behavior, FixtureBehavior::CloseWithoutStatus) {
                    session.close(channel)?;
                } else if !matches!(self.behavior, FixtureBehavior::EchoInput) {
                    session.exit_status_request(channel, 7)?;
                    session.eof(channel)?;
                    session.close(channel)?;
                }
            }
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if matches!(self.behavior, FixtureBehavior::EchoInput) {
                session.data(channel, data.to_vec())?;
            }
            Ok(())
        }

        async fn channel_eof(
            &mut self,
            channel: russh::ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if matches!(self.behavior, FixtureBehavior::EchoInput) {
                session.exit_status_request(channel, 7)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Ok(())
        }
    }

    async fn server_pair(
        client_stream: DuplexStream,
        server_stream: DuplexStream,
        identity: &PrivateKey,
        behavior: FixtureBehavior,
    ) -> (
        DuplexStream,
        JoinHandle<Result<(), russh::Error>>,
        PublicKey,
    ) {
        let server_key =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("fixture host key");
        let host_pin = server_key.public_key().clone();
        let config = Arc::new(server::Config {
            keys: vec![server_key],
            ..Default::default()
        });
        let handler = ShellHandler {
            authorized_key: identity.public_key().clone(),
            behavior,
        };
        let task = tokio::spawn(async move {
            let session = server::run_stream(config, server_stream, handler).await?;
            session.await
        });
        (client_stream, task, host_pin)
    }

    async fn authenticated_fixture(
        behavior: FixtureBehavior,
    ) -> (HostConnection, JoinHandle<Result<(), russh::Error>>) {
        let identity =
            PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("fixture client key");
        let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
        let (client_stream, task, pin) =
            server_pair(client_stream, server_stream, &identity, behavior).await;
        let session = crate::connect::connect_stream_authenticated(
            client_stream,
            "fixture-user",
            identity,
            pin,
        )
        .await
        .expect("authenticate fixture client");
        (HostConnection::from_authenticated_session(session), task)
    }

    #[tokio::test]
    async fn pty_shell_stream_and_exit_status_use_authenticated_session() {
        let (connection, server_task) = authenticated_fixture(FixtureBehavior::Accept).await;
        let mut input = io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let status = connection
            .interactive("xterm-test", 80, 24, &mut input, &mut output)
            .await
            .expect("interactive fixture session");
        assert_eq!(status, 7);
        assert_eq!(output, b"fixture-shell\r\n");
        connection.close().await.expect("close SSH session");
        server_task
            .await
            .expect("join server")
            .expect("server stopped");
    }

    #[tokio::test]
    async fn pty_and_shell_rejections_are_explicit() {
        for behavior in [FixtureBehavior::RejectPty, FixtureBehavior::RejectShell] {
            let (connection, server_task) = authenticated_fixture(behavior).await;
            let mut input = io::Cursor::new(Vec::<u8>::new());
            let mut output = Vec::new();
            let error = connection
                .interactive("xterm-test", 80, 24, &mut input, &mut output)
                .await
                .expect_err("fixture request rejected");
            assert!(error.to_string().contains("rejected"));
            connection.close().await.expect("close SSH session");
            server_task
                .await
                .expect("join server")
                .expect("server stopped");
        }
    }

    #[tokio::test]
    async fn interactive_input_preserves_control_and_ansi_bytes() {
        let (connection, server_task) = authenticated_fixture(FixtureBehavior::EchoInput).await;
        let bytes = [0x03, 0x04, 0x1b, b'[', b'A'];
        let mut input = io::Cursor::new(bytes);
        let mut output = Vec::new();
        let status = connection
            .interactive("xterm-test", 80, 24, &mut input, &mut output)
            .await
            .expect("interactive byte echo");
        assert_eq!(status, 7);
        assert_eq!(&output[..15], b"fixture-shell\r\n");
        assert_eq!(&output[15..], bytes);
        connection.close().await.expect("close SSH session");
        server_task
            .await
            .expect("join server")
            .expect("server stopped");
    }

    #[tokio::test]
    async fn close_without_exit_status_is_distinct_from_transport_close() {
        let (connection, server_task) =
            authenticated_fixture(FixtureBehavior::CloseWithoutStatus).await;
        let mut input = io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let error = connection
            .interactive("xterm-test", 80, 24, &mut input, &mut output)
            .await
            .expect_err("missing remote status");
        assert!(matches!(error, SshClientError::MissingExitStatus));
        connection.close().await.expect("close SSH session");
        server_task
            .await
            .expect("join server")
            .expect("server stopped");
    }
}
