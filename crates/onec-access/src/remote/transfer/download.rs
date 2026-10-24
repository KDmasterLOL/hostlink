//! Download retry, integrity verification, and atomic local publication.

use super::{
    FILE_TRANSFER_ATTEMPTS, FILE_TRANSFER_SHA256_CAPABILITY, copy_exact_with_progress,
    create_local_temp_file, is_transient_transfer_error, sftp_path, sha256_file_async,
};
use crate::remote::model::{RemoteAgentClient, RemoteCarrier};
use crate::remote::protocol::{read_response_unbuffered, response_into_kind, write_request};
use crate::{AppResult, io_error};
use onec_agent_protocol::{AgentRequest, AgentRequestKind, AgentResponseKind};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

impl RemoteAgentClient {
    /// Downloads one remote file with retry, integrity verification, and atomic local publication.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for transport/remote I/O, local publication, integrity, or
    /// overwrite-policy failure.
    pub async fn download(
        &self,
        remote_path: impl Into<String>,
        local_path: impl AsRef<Path>,
        overwrite: bool,
    ) -> AppResult<u64> {
        self.download_with_progress(remote_path, local_path, overwrite, |_, _| {})
            .await
    }

    /// Downloads one remote file while reporting copied/total byte progress.
    ///
    /// Remote SHA-256/size is captured before transfer when supported; local bytes are staged and
    /// verified before atomic publication.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for transport/remote I/O, local I/O/publication, integrity,
    /// overwrite-policy, or exhausted retry failures.
    pub async fn download_with_progress<F>(
        &self,
        remote_path: impl Into<String>,
        local_path: impl AsRef<Path>,
        overwrite: bool,
        mut progress: F,
    ) -> AppResult<u64>
    where
        F: FnMut(u64, u64),
    {
        let remote_path = remote_path.into();
        let local_path = local_path.as_ref();
        let expected = if self
            .supports_capability(FILE_TRANSFER_SHA256_CAPABILITY)
            .await?
        {
            Some(self.path_sha256(remote_path.clone()).await?)
        } else {
            None
        };

        for attempt in 1..FILE_TRANSFER_ATTEMPTS {
            match self
                .download_once(
                    &remote_path,
                    local_path,
                    overwrite,
                    expected.as_ref(),
                    &mut progress,
                )
                .await
            {
                Ok(copied) => return Ok(copied),
                Err(error) if should_retry_download(&error, attempt) => {
                    tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                }
                Err(error) => return Err(error),
            }
        }

        self.download_once(
            &remote_path,
            local_path,
            overwrite,
            expected.as_ref(),
            &mut progress,
        )
        .await
    }

    async fn download_once<F>(
        &self,
        remote_path: &str,
        local_path: &Path,
        overwrite: bool,
        expected: Option<&(u64, String)>,
        progress: &mut F,
    ) -> AppResult<u64>
    where
        F: FnMut(u64, u64),
    {
        if !overwrite && local_path.exists() {
            return Err(crate::invalid_config(format!(
                "download target already exists: {}",
                local_path.display()
            )));
        }
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }
        if self.server.carrier == RemoteCarrier::TargetSsh
            && let Some(copied) = self
                .download_sftp_once(remote_path, local_path, overwrite, expected, progress)
                .await?
        {
            return Ok(copied);
        }

        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::Download {
                path: remote_path.to_owned(),
            },
        );
        let mut channel = self.open_channel().await?;
        write_request(&mut channel, &request)
            .await
            .map_err(|source| {
                crate::invalid_config(format!("failed to send download request: {source}"))
            })?;
        channel.close_write().await?;

        let bytes = match response_into_kind(read_response_unbuffered(&mut channel).await?)? {
            AgentResponseKind::DownloadReady { bytes } => bytes,
            other => {
                return Err(crate::invalid_config(format!(
                    "agent returned unexpected download response: {other:?}"
                )));
            }
        };
        if let Some((expected_bytes, _)) = expected
            && *expected_bytes != bytes
        {
            return Err(crate::invalid_config(format!(
                "remote download size changed before transfer: expected {expected_bytes}, got {bytes}"
            )));
        }

        progress(0, bytes);
        let temp = transfer_temp_path(local_path);
        let (mut temp_guard, mut file) = create_local_temp_file(temp)?;
        let temp = temp_guard.path().to_path_buf();
        let copied = {
            let mut limited = (&mut channel).take(bytes);
            match copy_exact_with_progress(&mut limited, &mut file, bytes, progress).await {
                Ok(copied) => copied,
                Err(source) => {
                    drop(file);
                    temp_guard.cleanup_best_effort().await;
                    return Err(io_error(&temp, source));
                }
            }
        };
        if copied != bytes {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(crate::invalid_config(format!(
                "download ended after {copied} of {bytes} bytes"
            )));
        }
        if let Err(source) = file.sync_all().await {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(io_error(&temp, source));
        }
        drop(file);

        if let Err(error) = channel.finish().await {
            temp_guard.cleanup_best_effort().await;
            return Err(error);
        }
        publish_staged_file(
            &temp,
            local_path,
            overwrite,
            bytes,
            expected.map(|(_, sha256)| sha256.as_str()),
            &format!("remote download {remote_path}"),
        )
        .await?;
        temp_guard.disarm();
        Ok(copied)
    }

    async fn download_sftp_once<F>(
        &self,
        remote_path: &str,
        local_path: &Path,
        overwrite: bool,
        expected: Option<&(u64, String)>,
        progress: &mut F,
    ) -> AppResult<Option<u64>>
    where
        F: FnMut(u64, u64),
    {
        let source = sftp_path(remote_path);
        let temp = transfer_temp_path(local_path);
        let (mut temp_guard, mut file) = create_local_temp_file(temp)?;
        let temp = temp_guard.path().to_path_buf();

        let mut sftp = match self.open_sftp().await {
            Ok(Some(sftp)) => sftp,
            Ok(None) => {
                drop(file);
                temp_guard.cleanup_best_effort().await;
                return Ok(None);
            }
            Err(error) => {
                drop(file);
                temp_guard.cleanup_best_effort().await;
                return Err(error);
            }
        };
        let remote_bytes = match sftp.sftp_metadata_size(&source).await {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = sftp.finish().await;
                drop(file);
                temp_guard.cleanup_best_effort().await;
                return Err(error);
            }
        };
        if let Some((expected_bytes, _)) = expected
            && *expected_bytes != remote_bytes
        {
            let _ = sftp.finish().await;
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(crate::invalid_config(format!(
                "remote download size changed before SFTP transfer: expected {expected_bytes}, got {remote_bytes}"
            )));
        }

        progress(0, remote_bytes);
        let copied = match sftp.sftp_download(&source, &mut file, progress).await {
            Ok(copied) => copied,
            Err(error) => {
                let _ = sftp.finish().await;
                drop(file);
                temp_guard.cleanup_best_effort().await;
                return Err(error);
            }
        };
        if let Err(error) = sftp.finish().await {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(error);
        }
        if let Err(source) = file.sync_all().await {
            drop(file);
            temp_guard.cleanup_best_effort().await;
            return Err(io_error(&temp, source));
        }
        drop(file);

        publish_staged_file(
            &temp,
            local_path,
            overwrite,
            copied,
            expected.map(|(_, sha256)| sha256.as_str()),
            &format!("remote SFTP download {remote_path}"),
        )
        .await?;
        temp_guard.disarm();
        Ok(Some(copied))
    }
}

fn should_retry_download(error: &crate::AppError, attempt: usize) -> bool {
    attempt < FILE_TRANSFER_ATTEMPTS && is_transient_transfer_error(error)
}

pub(super) async fn publish_staged_file(
    temp: &Path,
    local_path: &Path,
    overwrite: bool,
    expected_bytes: u64,
    expected_sha256: Option<&str>,
    description: &str,
) -> AppResult<()> {
    let actual_bytes = match fs::metadata(temp) {
        Ok(metadata) => metadata.len(),
        Err(source) => {
            let _ = fs::remove_file(temp);
            return Err(io_error(temp, source));
        }
    };
    if actual_bytes != expected_bytes {
        let _ = fs::remove_file(temp);
        return Err(crate::invalid_config(format!(
            "{description} size mismatch: expected {expected_bytes}, got {actual_bytes}"
        )));
    }
    if let Some(expected_sha256) = expected_sha256 {
        let actual_sha256 = match sha256_file_async(temp).await {
            Ok(sha256) => sha256,
            Err(error) => {
                let _ = fs::remove_file(temp);
                return Err(error);
            }
        };
        if actual_sha256 != expected_sha256 {
            let _ = fs::remove_file(temp);
            return Err(crate::invalid_config(format!(
                "{description} SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
            )));
        }
    }
    let publication = if overwrite {
        onec_core::replace_file_atomically(temp, local_path)
    } else {
        onec_core::move_file_atomically(temp, local_path)
    };
    if let Err(source) = publication {
        let _ = fs::remove_file(temp);
        return Err(io_error(local_path, source));
    }
    Ok(())
}

pub(super) fn transfer_temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("onec-download");
    path.with_file_name(format!(
        ".{name}.onec-download-{}.tmp",
        Uuid::new_v4().simple()
    ))
}

#[cfg(test)]
mod tests {
    use super::{publish_staged_file, should_retry_download, transfer_temp_path};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Write};

    #[test]
    fn download_retry_is_bounded_and_excludes_ambiguous_failures() {
        use crate::AppError;
        use std::io;

        let reset = AppError::new(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection reset before download completed",
        ));
        assert!(should_retry_download(&reset, 1));
        assert!(should_retry_download(&reset, 2));
        assert!(!should_retry_download(&reset, 3));

        for error in [
            AppError::new(io::Error::new(io::ErrorKind::TimedOut, "timed out")),
            crate::invalid_config("permission denied"),
            crate::invalid_config("download SHA-256 mismatch"),
            crate::invalid_config("remote outcome unknown"),
        ] {
            assert!(!should_retry_download(&error, 1), "{error}");
        }
    }

    #[tokio::test]
    async fn verified_staged_publication_rejects_bad_digest_without_replacing_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("report.bin");
        let temp = transfer_temp_path(&target);
        let mut file = fs::File::create(&temp).expect("staged file");
        file.write_all(b"staged result").expect("staged bytes");
        file.sync_all().expect("sync staged file");
        fs::write(&target, b"existing target").expect("existing target");
        let expected = format!("{:x}", Sha256::digest(b"expected result"));

        let error = publish_staged_file(
            &temp,
            &target,
            true,
            b"staged result".len() as u64,
            Some(&expected),
            "managed result",
        )
        .await
        .expect_err("digest mismatch must block publication");

        assert!(error.to_string().contains("SHA-256 mismatch"));
        assert_eq!(
            fs::read(&target).expect("preserved target"),
            b"existing target"
        );
        assert!(!temp.exists());
    }

    #[tokio::test]
    async fn verified_staged_publication_atomically_publishes_exact_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("report.bin");
        let temp = transfer_temp_path(&target);
        let bytes = b"verified artifact";
        let mut file = fs::File::create(&temp).expect("staged file");
        file.write_all(bytes).expect("staged bytes");
        file.sync_all().expect("sync staged file");
        let expected = format!("{:x}", Sha256::digest(bytes));

        publish_staged_file(
            &temp,
            &target,
            false,
            bytes.len() as u64,
            Some(&expected),
            "managed result",
        )
        .await
        .expect("publish verified result");

        assert_eq!(fs::read(&target).expect("published result"), bytes);
        assert!(!temp.exists());
    }

    #[tokio::test]
    async fn verified_staged_publication_atomically_replaces_existing_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("report.bin");
        let temp = transfer_temp_path(&target);
        let bytes = b"new verified artifact";
        fs::write(&target, b"old verified artifact").expect("existing target");
        let mut file = fs::File::create(&temp).expect("staged file");
        file.write_all(bytes).expect("staged bytes");
        file.sync_all().expect("sync staged file");

        publish_staged_file(
            &temp,
            &target,
            true,
            bytes.len() as u64,
            None,
            "managed result",
        )
        .await
        .expect("replace verified result");

        assert_eq!(fs::read(&target).expect("published result"), bytes);
        assert!(!temp.exists());
    }

    #[tokio::test]
    async fn verified_staged_publication_no_overwrite_preserves_existing_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("report.bin");
        let temp = transfer_temp_path(&target);
        fs::write(&target, b"existing target").expect("existing target");
        let mut file = fs::File::create(&temp).expect("staged file");
        file.write_all(b"staged result").expect("staged bytes");
        file.sync_all().expect("sync staged file");

        publish_staged_file(
            &temp,
            &target,
            false,
            b"staged result".len() as u64,
            None,
            "managed result",
        )
        .await
        .expect_err("no-overwrite publication must fail when target exists");

        assert_eq!(
            fs::read(&target).expect("preserved target"),
            b"existing target"
        );
        assert!(!temp.exists());
    }
}
