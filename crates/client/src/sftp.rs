//! Bounded SFTP upload and download over the authenticated SSH connection.

use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connect::{HostConnection, MAX_TRANSFER_BYTES, OPERATION_TIMEOUT, SshClientError};

impl HostConnection {
    /// Creates one new remote SFTP file and uploads a bounded byte slice.
    ///
    /// # Errors
    /// Returns an error for an empty path, oversized data, an existing target,
    /// SFTP rejection, transport failure, or timeout.
    pub async fn sftp_upload(
        &mut self,
        remote_path: &str,
        data: &[u8],
    ) -> Result<(), SshClientError> {
        if remote_path.is_empty() {
            return Err(SshClientError::Invalid("SFTP path is empty".into()));
        }
        if data.len() > MAX_TRANSFER_BYTES {
            return Err(SshClientError::TransferTooLarge);
        }
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            let sftp = self.open_sftp().await?;
            let mut file = sftp
                .open_with_flags(
                    remote_path.to_owned(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await?;
            file.write_all(data).await?;
            file.close().await?;
            sftp.close().await?;
            Ok(())
        })
        .await
        .map_err(|_| SshClientError::Timeout)?
    }

    /// Downloads one bounded remote SFTP file as raw bytes.
    ///
    /// # Errors
    /// Returns an error for an empty path, oversized data, SFTP rejection,
    /// transport failure, or timeout.
    pub async fn sftp_download(&mut self, remote_path: &str) -> Result<Vec<u8>, SshClientError> {
        if remote_path.is_empty() {
            return Err(SshClientError::Invalid("SFTP path is empty".into()));
        }
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            let sftp = self.open_sftp().await?;
            let mut file = sftp.open(remote_path.to_owned()).await?;
            let mut data = Vec::new();
            (&mut file)
                .take((MAX_TRANSFER_BYTES + 1) as u64)
                .read_to_end(&mut data)
                .await?;
            if data.len() > MAX_TRANSFER_BYTES {
                return Err(SshClientError::TransferTooLarge);
            }
            file.close().await?;
            sftp.close().await?;
            Ok(data)
        })
        .await
        .map_err(|_| SshClientError::Timeout)?
    }

    async fn open_sftp(&self) -> Result<russh_sftp::client::SftpSession, SshClientError> {
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        Ok(russh_sftp::client::SftpSession::new(channel.into_stream()).await?)
    }
}
