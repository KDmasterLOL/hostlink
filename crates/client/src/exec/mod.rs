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
mod tests;
