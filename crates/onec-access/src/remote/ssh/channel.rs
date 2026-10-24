//! Operation-scoped SSH channel and SFTP lifecycle.

use super::connect::{ConnectionCleanupUnconfirmed, close_session};
use super::trust::StrictKnownHost;
use crate::remote::model::{RemoteAgentClient, RemoteCarrier};
use crate::remote::{SFTP_IO_STAGE_DEADLINE, UploadStage, sftp_stage};
use crate::{AppResult, invalid_config};
use anyhow::Context;
use russh::client;
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{OpenFlags, StatusCode};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub(in crate::remote) struct EmbeddedSshChannel {
    pub(super) gateway_session: Option<client::Handle<StrictKnownHost>>,
    pub(super) target_session: Option<client::Handle<StrictKnownHost>>,
    pub(super) stream: Option<russh::ChannelStream<client::Msg>>,
    pub(super) sftp: Option<SftpSession>,
    pub(super) write_closed: bool,
    pub(super) finished: bool,
}

impl EmbeddedSshChannel {
    pub(in crate::remote) async fn close_write(&mut self) -> AppResult<()> {
        if self.write_closed {
            return Ok(());
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| invalid_config("embedded SSH channel has no raw stream".to_owned()))?;
        stream
            .shutdown()
            .await
            .context("closing embedded SSH channel write side")?;
        self.write_closed = true;
        Ok(())
    }

    pub(in crate::remote) async fn finish(&mut self) -> AppResult<()> {
        if self.finished {
            return Ok(());
        }
        let primary_error = if let Some(sftp) = self.sftp.take() {
            sftp.close()
                .await
                .context("closing target SFTP session")
                .err()
        } else {
            self.close_write().await.err()
        };
        let target_session = self.target_session.take();
        let gateway_session = self.gateway_session.take();
        let (target_cleanup, gateway_cleanup) = attempt_both(
            async move {
                match target_session {
                    Some(mut session) => {
                        close_session(&mut session, "target request complete", None).await
                    }
                    None => Ok(()),
                }
            },
            async move {
                match gateway_session {
                    Some(mut session) => {
                        close_session(&mut session, "gateway request complete", None).await
                    }
                    None => Ok(()),
                }
            },
        )
        .await;
        finish_cleanup_result(primary_error, target_cleanup, gateway_cleanup)?;
        self.finished = true;
        Ok(())
    }

    pub(in crate::remote) async fn sftp_try_exists(&self, path: &str) -> AppResult<bool> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        sftp.try_exists(path.to_owned())
            .await
            .with_context(|| format!("checking SFTP path {path:?}"))
    }

    pub(in crate::remote) async fn sftp_metadata_size(&self, path: &str) -> AppResult<u64> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        let metadata = sftp
            .metadata(path.to_owned())
            .await
            .with_context(|| format!("reading SFTP metadata for {path:?}"))?;
        metadata.size.ok_or_else(|| {
            invalid_config(format!("SFTP server did not report file size for {path:?}"))
        })
    }

    pub(in crate::remote) async fn sftp_upload<R, F>(
        &mut self,
        input: &mut R,
        remote_path: &str,
        total: u64,
        progress: &mut F,
        set_stage: &mut impl FnMut(UploadStage),
        total_deadline: tokio::time::Instant,
    ) -> AppResult<u64>
    where
        R: AsyncRead + Unpin,
        F: FnMut(u64, u64),
    {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        set_stage(UploadStage::SftpFileOpen);
        let mut remote = sftp_stage(
            "sftp_file_open",
            SFTP_IO_STAGE_DEADLINE,
            total_deadline,
            0,
            total,
            async {
                sftp.open_with_flags(
                    remote_path.to_owned(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                )
                .await
                .with_context(|| "creating SFTP staging file")
            },
        )
        .await?;

        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        while copied < total {
            let remaining = usize::try_from((total - copied).min(buffer.len() as u64))
                .expect("bounded SFTP chunk length");
            let read = input
                .read(&mut buffer[..remaining])
                .await
                .with_context(|| format!("reading local bytes for SFTP upload {remote_path:?}"))?;
            if read == 0 {
                set_stage(UploadStage::SftpClose);
                let _ = sftp_stage(
                    "sftp_close",
                    SFTP_IO_STAGE_DEADLINE,
                    total_deadline,
                    copied,
                    total,
                    async {
                        remote
                            .close()
                            .await
                            .context("closing SFTP staging file after local EOF")
                    },
                )
                .await;
                return Err(invalid_config(format!(
                    "local SFTP upload ended after {copied} of {total} bytes"
                )));
            }
            set_stage(UploadStage::SftpWrite);
            sftp_stage(
                "sftp_write",
                SFTP_IO_STAGE_DEADLINE,
                total_deadline,
                copied,
                total,
                async {
                    remote
                        .write_all(&buffer[..read])
                        .await
                        .with_context(|| "writing SFTP staging file")
                },
            )
            .await?;
            copied += read as u64;
            progress(copied, total);
        }
        set_stage(UploadStage::SftpSync);
        sftp_stage(
            "sftp_sync",
            SFTP_IO_STAGE_DEADLINE,
            total_deadline,
            copied,
            total,
            async {
                remote
                    .sync_all()
                    .await
                    .with_context(|| "syncing SFTP staging file")
            },
        )
        .await?;
        set_stage(UploadStage::SftpClose);
        sftp_stage(
            "sftp_close",
            SFTP_IO_STAGE_DEADLINE,
            total_deadline,
            copied,
            total,
            async {
                remote
                    .close()
                    .await
                    .with_context(|| "closing SFTP staging file")
            },
        )
        .await?;
        Ok(copied)
    }

    pub(in crate::remote) async fn sftp_download<W, F>(
        &mut self,
        remote_path: &str,
        output: &mut W,
        progress: &mut F,
    ) -> AppResult<u64>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(u64, u64),
    {
        let total = self.sftp_metadata_size(remote_path).await?;
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        let mut remote = sftp
            .open(remote_path.to_owned())
            .await
            .with_context(|| format!("opening SFTP download source {remote_path:?}"))?;
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = remote
                .read(&mut buffer)
                .await
                .with_context(|| format!("reading SFTP source {remote_path:?}"))?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .await
                .with_context(|| format!("writing local bytes from SFTP {remote_path:?}"))?;
            copied += read as u64;
            progress(copied, total);
        }
        remote
            .close()
            .await
            .with_context(|| format!("closing SFTP source {remote_path:?}"))?;
        if copied != total {
            return Err(invalid_config(format!(
                "SFTP download ended after {copied} of {total} bytes for {remote_path:?}"
            )));
        }
        Ok(copied)
    }

    pub(in crate::remote) async fn sftp_remove_file(&self, path: &str) -> AppResult<()> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        sftp.remove_file(path.to_owned())
            .await
            .with_context(|| format!("removing SFTP file {path:?}"))
    }

    pub(in crate::remote) async fn bridge_tcp(
        mut self,
        mut local: tokio::net::TcpStream,
    ) -> AppResult<()> {
        let stream = self
            .stream
            .as_mut()
            .expect("embedded SSH stream must exist until drop");
        tokio::io::copy_bidirectional(&mut local, stream)
            .await
            .context("bridging local TCP stream over embedded SSH channel")?;
        self.finish().await
    }
}

impl RemoteAgentClient {
    pub(in crate::remote) async fn open_channel(&self) -> AppResult<EmbeddedSshChannel> {
        EmbeddedSshChannel::connect_control(&self.server).await
    }

    pub(in crate::remote) async fn open_target_tcp_channel(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> AppResult<EmbeddedSshChannel> {
        EmbeddedSshChannel::connect_target_tcp(&self.server, host, port, timeout).await
    }

    pub(in crate::remote) async fn open_sftp(&self) -> AppResult<Option<EmbeddedSshChannel>> {
        EmbeddedSshChannel::connect_sftp(&self.server).await
    }

    pub(crate) async fn target_sftp_path_is_absent(&self, path: &str) -> AppResult<bool> {
        // Gateway-control transport has no target SSH/SFTP channel. Its inability to
        // prove absence must not be mistaken for a missing content-addressed file.
        if self.server.carrier != RemoteCarrier::TargetSsh {
            return Err(crate::remote::sftp_carrier_unavailable_error());
        }
        let Some(mut channel) = self.open_sftp().await? else {
            return Err(crate::remote::sftp_not_offered_error());
        };
        let sftp = channel
            .sftp
            .as_ref()
            .ok_or_else(|| invalid_config("embedded channel is not an SFTP session".to_owned()))?;
        let absent = match sftp.symlink_metadata(path.to_owned()).await {
            Ok(metadata) if metadata.is_symlink() => {
                return Err(invalid_config(
                    "managed SFTP cache path is a symlink; cache upload skipped".to_owned(),
                ));
            }
            Ok(_) => false,
            Err(error) if sftp_error_is_no_such_file(&error) => true,
            Err(error) => {
                return Err(anyhow::Error::new(error).context(
                    "managed SFTP could not prove cache path absence; cache upload skipped",
                ));
            }
        };
        channel.finish().await?;
        Ok(absent)
    }
}

pub(super) fn sftp_error_is_no_such_file(error: &SftpError) -> bool {
    matches!(error, SftpError::Status(status) if status.status_code == StatusCode::NoSuchFile)
}

impl AsyncRead for EmbeddedSshChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = self
            .stream
            .as_mut()
            .expect("embedded SSH stream must exist until drop");
        Pin::new(stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for EmbeddedSshChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = self
            .stream
            .as_mut()
            .expect("embedded SSH stream must exist until drop");
        Pin::new(stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let stream = self
            .stream
            .as_mut()
            .expect("embedded SSH stream must exist until drop");
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let stream = self
            .stream
            .as_mut()
            .expect("embedded SSH stream must exist until drop");
        Pin::new(stream).poll_shutdown(cx)
    }
}

pub(super) async fn attempt_both<T, G>(target: T, gateway: G) -> (AppResult<()>, AppResult<()>)
where
    T: Future<Output = AppResult<()>>,
    G: Future<Output = AppResult<()>>,
{
    let target = target.await;
    let gateway = gateway.await;
    (target, gateway)
}

pub(super) fn finish_cleanup_result(
    primary_error: Option<anyhow::Error>,
    target_cleanup: AppResult<()>,
    gateway_cleanup: AppResult<()>,
) -> AppResult<()> {
    if target_cleanup.is_err() || gateway_cleanup.is_err() {
        return Err(ConnectionCleanupUnconfirmed(primary_error).into());
    }
    if let Some(primary) = primary_error {
        return Err(primary);
    }
    Ok(())
}
