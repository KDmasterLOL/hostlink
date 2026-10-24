//! Upload retry, integrity verification, and streaming publication.

use super::{
    FILE_TRANSFER_ATTEMPTS, FILE_TRANSFER_SHA256_CAPABILITY, RemoteStagingGuard,
    SFTP_IO_STAGE_DEADLINE, UploadStage, copy_exact_with_progress, is_transient_transfer_error,
    sftp_path, sftp_stage, sftp_staging_path, sha256_file_async,
};
use crate::remote::model::{RemoteAgentClient, RemoteCarrier};
use crate::remote::protocol::{read_response_unbuffered, response_into_kind, write_request};
use crate::{AppError, AppResult, io_error};
use onec_agent_protocol::{AgentRequest, AgentRequestKind, AgentResponseKind};
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::Duration;

const TARGET_SSH_UPLOAD_DEADLINE: Duration = Duration::from_secs(180);
// Agent PathSha256 runs through the authenticated control channel, not SFTP.
// Use a separate bound: large-file hashing can legitimately outlast one SFTP stage.
const AGENT_SHA256_RPC_DEADLINE: Duration = Duration::from_secs(180);
const REMOTE_STAGING_CLEANUP_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct UploadProgressState {
    stage: Arc<AtomicU8>,
    // Progress from SFTP AsyncWrite is not proof of a server reply or publication.
    // Keep the emitted `acknowledged_bytes` key stable for existing diagnostic consumers.
    acknowledged_bytes: Arc<AtomicU64>,
    total_bytes: Arc<AtomicU64>,
    publication_started: Arc<std::sync::atomic::AtomicBool>,
    total_deadline: tokio::time::Instant,
    started_at: std::time::Instant,
}

impl UploadProgressState {
    fn new(total_deadline: tokio::time::Instant, started_at: std::time::Instant) -> Self {
        Self {
            stage: Arc::new(AtomicU8::new(UploadStage::Preflight as u8)),
            acknowledged_bytes: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            publication_started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            total_deadline,
            started_at,
        }
    }

    fn set_stage(&self, stage: UploadStage) {
        self.stage.store(stage as u8, Ordering::Relaxed);
    }

    fn stage_label(&self) -> &'static str {
        match self.stage.load(Ordering::Relaxed) {
            value if value == UploadStage::SftpOpen as u8 => UploadStage::SftpOpen.label(),
            value if value == UploadStage::SftpDestinationCheck as u8 => {
                UploadStage::SftpDestinationCheck.label()
            }
            value if value == UploadStage::SftpWrite as u8 => UploadStage::SftpWrite.label(),
            value if value == UploadStage::SftpFileOpen as u8 => UploadStage::SftpFileOpen.label(),
            value if value == UploadStage::SftpSync as u8 => UploadStage::SftpSync.label(),
            value if value == UploadStage::SftpClose as u8 => UploadStage::SftpClose.label(),
            value if value == UploadStage::SftpSessionClose as u8 => {
                UploadStage::SftpSessionClose.label()
            }
            value if value == UploadStage::SftpCleanup as u8 => UploadStage::SftpCleanup.label(),
            value if value == UploadStage::SftpMetadata as u8 => UploadStage::SftpMetadata.label(),
            value if value == UploadStage::SftpHash as u8 => UploadStage::SftpHash.label(),
            value if value == UploadStage::Publication as u8 => UploadStage::Publication.label(),
            value if value == UploadStage::FinalVerification as u8 => {
                UploadStage::FinalVerification.label()
            }
            value if value == UploadStage::AgentTransfer as u8 => {
                UploadStage::AgentTransfer.label()
            }
            _ => UploadStage::Preflight.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadFailureStage {
    BeforePublication,
    BeforePublicationCleanupUnconfirmed,
    PublicationMayHaveCommitted,
}

#[derive(Debug)]
struct UploadFailure {
    error: AppError,
    stage: UploadFailureStage,
}

impl UploadFailure {
    fn before_publication(error: AppError) -> Self {
        Self {
            error,
            stage: UploadFailureStage::BeforePublication,
        }
    }

    fn publication_may_have_committed(error: AppError) -> Self {
        Self {
            error,
            stage: UploadFailureStage::PublicationMayHaveCommitted,
        }
    }

    fn before_publication_cleanup_unconfirmed(error: AppError) -> Self {
        Self {
            error,
            stage: UploadFailureStage::BeforePublicationCleanupUnconfirmed,
        }
    }
}

impl From<AppError> for UploadFailure {
    fn from(error: AppError) -> Self {
        Self::before_publication(error)
    }
}

fn should_retry_upload_failure(failure: &UploadFailure, attempt: usize) -> bool {
    failure.stage == UploadFailureStage::BeforePublication
        && attempt < FILE_TRANSFER_ATTEMPTS
        && is_transient_transfer_error(&failure.error)
}

fn cleanup_failure_kind(error: &AppError) -> &'static str {
    if let Some(source) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        return match source.kind() {
            std::io::ErrorKind::TimedOut => "timeout",
            std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => "transport",
            std::io::ErrorKind::PermissionDenied => "permission",
            std::io::ErrorKind::NotFound => "missing",
            _ => "io_error",
        };
    }

    let details = error.to_string().to_ascii_lowercase();
    if details.contains("deadline exceeded") || details.contains("timed out") {
        "timeout"
    } else if details.contains("connection") || details.contains("transport") {
        "transport"
    } else if details.contains("permission") {
        "permission"
    } else {
        "remote_error"
    }
}

fn failure_after_staging_cleanup(
    mut failure: UploadFailure,
    cause_stage: &'static str,
    cleanup: AppResult<()>,
    staging_guard: &mut RemoteStagingGuard,
) -> UploadFailure {
    match cleanup {
        Ok(()) => {
            staging_guard.disarm();
            failure
        }
        Err(cleanup_error) if failure.stage == UploadFailureStage::BeforePublication => {
            let cleanup_kind = cleanup_failure_kind(&cleanup_error);
            failure.error = failure.error.context(format!(
                "upload staging cleanup unconfirmed (cleanup=unconfirmed cause_stage={cause_stage} cleanup_stage=staging_cleanup cleanup_failure={cleanup_kind})"
            ));
            UploadFailure::before_publication_cleanup_unconfirmed(failure.error)
        }
        Err(_) => failure,
    }
}

impl RemoteAgentClient {
    /// Uploads one local file with retry, staged publication, and integrity verification when supported.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for local I/O, capability/transport, remote publication, integrity,
    /// or overwrite-policy failure.
    pub async fn upload(
        &self,
        local_path: impl AsRef<Path>,
        remote_path: impl Into<String>,
        overwrite: bool,
    ) -> AppResult<u64> {
        self.upload_with_progress(local_path, remote_path, overwrite, |_, _| {})
            .await
    }

    /// Uploads one local file while reporting copied/total byte progress.
    ///
    /// Target-SSH uses SFTP staging/publication; gateway-control uses the resident agent protocol.
    /// When remote SHA-256 is available the final bytes/digest must match before success is returned.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] for local I/O, capability/transport, publication, integrity,
    /// overwrite-policy, or exhausted retry failures.
    pub async fn upload_with_progress<F>(
        &self,
        local_path: impl AsRef<Path>,
        remote_path: impl Into<String>,
        overwrite: bool,
        progress: F,
    ) -> AppResult<u64>
    where
        F: FnMut(u64, u64),
    {
        self.upload_with_progress_deadline(
            local_path,
            remote_path,
            overwrite,
            progress,
            TARGET_SSH_UPLOAD_DEADLINE,
        )
        .await
    }

    pub(in crate::remote) async fn upload_with_progress_deadline<F>(
        &self,
        local_path: impl AsRef<Path>,
        remote_path: impl Into<String>,
        overwrite: bool,
        mut progress: F,
        deadline: Duration,
    ) -> AppResult<u64>
    where
        F: FnMut(u64, u64),
    {
        let tokio_started_at = tokio::time::Instant::now();
        let started_at = std::time::Instant::now();
        let total_deadline = tokio_started_at + deadline;
        let state = UploadProgressState::new(total_deadline, started_at);
        let callback_state = state.clone();
        let mut tracked_progress = move |copied, total| {
            callback_state.total_bytes.store(total, Ordering::Relaxed);
            callback_state
                .acknowledged_bytes
                .store(copied, Ordering::Relaxed);
            progress(copied, total);
        };
        let operation = Box::pin(self.upload_with_progress_inner(
            local_path.as_ref(),
            remote_path.into(),
            overwrite,
            &mut tracked_progress,
            &state,
        ));
        if self.server.carrier == RemoteCarrier::TargetSsh {
            return match tokio::time::timeout_at(total_deadline, operation).await {
                Ok(result) => result,
                Err(_) => {
                    let publication = if state.publication_started.load(Ordering::Relaxed) {
                        "may_have_committed"
                    } else {
                        "not_started"
                    };
                    let stage = state.stage_label();
                    let acknowledged = state.acknowledged_bytes.load(Ordering::Relaxed);
                    let total = state.total_bytes.load(Ordering::Relaxed);
                    let elapsed_ms = started_at.elapsed().as_millis();
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "onec-access upload outcome: phase=total_deadline stage={stage} elapsed_ms={elapsed_ms} acknowledged_bytes={acknowledged}/{total} publication={publication} remote_state=unknown"
                    );
                    Err(crate::invalid_config(format!(
                        "target SSH upload deadline exceeded (phase=total_deadline stage={stage} elapsed_ms={elapsed_ms} acknowledged_bytes={acknowledged}/{total} publication={publication} remote_state=unknown)"
                    )))
                }
            };
        }
        operation.await
    }

    async fn upload_with_progress_inner<F>(
        &self,
        local_path: &Path,
        remote_path: String,
        overwrite: bool,
        mut progress: F,
        state: &UploadProgressState,
    ) -> AppResult<u64>
    where
        F: FnMut(u64, u64),
    {
        let bytes = fs::metadata(local_path)
            .map_err(|source| io_error(local_path, source))?
            .len();
        let strong_verification = self
            .supports_capability(FILE_TRANSFER_SHA256_CAPABILITY)
            .await?;
        let expected_sha256 = if strong_verification {
            Some(sha256_file_async(local_path).await?)
        } else {
            None
        };
        for attempt in 1..=FILE_TRANSFER_ATTEMPTS {
            state.publication_started.store(false, Ordering::Relaxed);
            state.set_stage(UploadStage::Preflight);
            match self
                .upload_once(
                    local_path,
                    &remote_path,
                    overwrite,
                    expected_sha256.as_deref(),
                    &mut progress,
                    state,
                )
                .await
            {
                Ok(copied) => {
                    if let Some(expected) = expected_sha256.as_deref() {
                        state.set_stage(UploadStage::FinalVerification);
                        let (remote_bytes, actual) = sftp_stage(
                            "final_agent_sha256",
                            AGENT_SHA256_RPC_DEADLINE,
                            state.total_deadline,
                            bytes,
                            bytes,
                            Box::pin(self.path_sha256(remote_path.clone())),
                        )
                        .await?;
                        if remote_bytes != bytes || actual != expected {
                            return Err(crate::invalid_config(format!(
                                "remote upload integrity mismatch for {remote_path}: expected {bytes} bytes / {expected}, got {remote_bytes} bytes / {actual}"
                            )));
                        }
                    }
                    return Ok(copied);
                }
                Err(UploadFailure {
                    error,
                    stage: UploadFailureStage::PublicationMayHaveCommitted,
                }) => {
                    // For overwrite=false, matching remote bytes do not prove ownership:
                    // another writer can publish identical bytes after our existence check,
                    // while the refusal's response is lost. Fail closed on ambiguity.
                    if overwrite
                        && let Some(expected) = expected_sha256.as_deref()
                        && let Ok((remote_bytes, actual)) = sftp_stage(
                            "agent_publication_reconciliation",
                            AGENT_SHA256_RPC_DEADLINE,
                            state.total_deadline,
                            bytes,
                            bytes,
                            Box::pin(self.path_sha256(remote_path.clone())),
                        )
                        .await
                        && remote_bytes == bytes
                        && actual == expected
                    {
                        return Ok(bytes);
                    }
                    return Err(error);
                }
                Err(failure) => {
                    if !should_retry_upload_failure(&failure, attempt) {
                        return Err(failure.error);
                    }
                    tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                }
            }
        }

        Err(crate::invalid_config(format!(
            "upload to {remote_path} exhausted retry attempts without a terminal result"
        )))
    }

    async fn upload_once<F>(
        &self,
        local_path: &Path,
        remote_path: &str,
        overwrite: bool,
        expected_sha256: Option<&str>,
        progress: &mut F,
        state: &UploadProgressState,
    ) -> Result<u64, UploadFailure>
    where
        F: FnMut(u64, u64),
    {
        if self.server.carrier == RemoteCarrier::TargetSsh
            && let Some(copied) = self
                .upload_sftp_once(
                    local_path,
                    remote_path,
                    overwrite,
                    expected_sha256,
                    progress,
                    state,
                )
                .await?
        {
            return Ok(copied);
        }

        let mut file = tokio::fs::File::open(local_path)
            .await
            .map_err(|source| io_error(local_path, source))?;
        let bytes = file
            .metadata()
            .await
            .map_err(|source| io_error(local_path, source))?
            .len();
        progress(0, bytes);

        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::Upload {
                path: remote_path.to_owned(),
                bytes,
                overwrite,
            },
        );
        state.set_stage(UploadStage::AgentTransfer);
        let mut channel = self.open_channel().await?;
        write_request(&mut channel, &request).await?;
        let ready_response = read_response_unbuffered(&mut channel).await?;
        if !ready_response.ok {
            return Err(UploadFailure::before_publication(
                response_into_kind(ready_response).expect_err("failed response is an error"),
            ));
        }
        match response_into_kind(ready_response)? {
            AgentResponseKind::UploadReady => {}
            other => {
                return Err(UploadFailure::before_publication(crate::invalid_config(
                    format!("agent returned unexpected upload response: {other:?}"),
                )));
            }
        }

        let copied = copy_exact_with_progress(&mut file, &mut channel, bytes, progress)
            .await
            .map_err(|source| io_error(local_path, source))?;
        if copied != bytes {
            return Err(UploadFailure::before_publication(crate::invalid_config(
                format!("local upload produced {copied} of {bytes} bytes"),
            )));
        }
        state.publication_started.store(true, Ordering::Relaxed);
        channel
            .close_write()
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;

        let done_response = read_response_unbuffered(&mut channel)
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        if !done_response.ok {
            return Err(UploadFailure::before_publication(
                response_into_kind(done_response).expect_err("failed response is an error"),
            ));
        }
        let done = response_into_kind(done_response)
            .map_err(UploadFailure::publication_may_have_committed)?;
        match done {
            AgentResponseKind::Uploaded { bytes: uploaded } if uploaded == bytes => {}
            other => {
                return Err(UploadFailure::publication_may_have_committed(
                    crate::invalid_config(format!(
                        "agent returned unexpected upload completion: {other:?}"
                    )),
                ));
            }
        }
        channel
            .finish()
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        Ok(copied)
    }

    async fn upload_sftp_once<F>(
        &self,
        local_path: &Path,
        remote_path: &str,
        overwrite: bool,
        expected_sha256: Option<&str>,
        progress: &mut F,
        state: &UploadProgressState,
    ) -> Result<Option<u64>, UploadFailure>
    where
        F: FnMut(u64, u64),
    {
        let destination = sftp_path(remote_path);
        let staging = sftp_staging_path(&destination)?;
        let mut file = tokio::fs::File::open(local_path)
            .await
            .map_err(|source| io_error(local_path, source))?;
        let bytes = file
            .metadata()
            .await
            .map_err(|source| io_error(local_path, source))?
            .len();
        progress(0, bytes);

        state.set_stage(UploadStage::SftpOpen);
        let Some(mut sftp) = sftp_stage(
            "sftp_open",
            SFTP_IO_STAGE_DEADLINE,
            state.total_deadline,
            0,
            bytes,
            self.open_sftp(),
        )
        .await?
        else {
            return Ok(None);
        };

        // A failure here is still before the toolkit-owned staging path can be created. Keep it
        // outside the staging guard so a failed destination check cannot report an orphan or
        // schedule cleanup for a path this upload never owned.
        state.set_stage(UploadStage::SftpDestinationCheck);
        if !overwrite {
            match sftp_stage(
                "sftp_destination_check",
                SFTP_IO_STAGE_DEADLINE,
                state.total_deadline,
                0,
                bytes,
                sftp.sftp_try_exists(&destination),
            )
            .await
            {
                Ok(true) => {
                    state.set_stage(UploadStage::SftpSessionClose);
                    let _ = sftp_stage(
                        "sftp_session_close",
                        SFTP_IO_STAGE_DEADLINE,
                        state.total_deadline,
                        0,
                        bytes,
                        sftp.finish(),
                    )
                    .await;
                    return Err(UploadFailure::before_publication(crate::invalid_config(
                        format!("upload target already exists: {remote_path}"),
                    )));
                }
                Ok(false) => {}
                Err(error) => {
                    state.set_stage(UploadStage::SftpSessionClose);
                    let _ = sftp_stage(
                        "sftp_session_close",
                        SFTP_IO_STAGE_DEADLINE,
                        state.total_deadline,
                        0,
                        bytes,
                        sftp.finish(),
                    )
                    .await;
                    return Err(UploadFailure::before_publication(error));
                }
            }
        }

        let cleanup_client = self.clone();
        let cleanup_path = staging.clone();
        let diagnostic_state = state.clone();
        let mut staging_guard = RemoteStagingGuard::new(move || {
            Box::pin(async move {
                let cleanup = async {
                    if let Ok(Some(mut cleanup_sftp)) = cleanup_client.open_sftp().await {
                        let _ = cleanup_sftp.sftp_remove_file(&cleanup_path).await;
                        let _ = cleanup_sftp.finish().await;
                    }
                };
                let _ = tokio::time::timeout(REMOTE_STAGING_CLEANUP_DEADLINE, cleanup).await;
            })
        })
        .with_diagnostic(move || {
            let publication = if diagnostic_state
                .publication_started
                .load(Ordering::Relaxed)
            {
                "may_have_committed"
            } else {
                "not_started"
            };
            format!(
                "state=unconfirmed stage={} elapsed_ms={} acknowledged_bytes={}/{} publication={publication}",
                diagnostic_state.stage_label(),
                diagnostic_state.started_at.elapsed().as_millis(),
                diagnostic_state.acknowledged_bytes.load(Ordering::Relaxed),
                diagnostic_state.total_bytes.load(Ordering::Relaxed),
            )
        });
        let transfer = async {
            state.set_stage(UploadStage::SftpWrite);
            let mut set_stage = |stage| state.set_stage(stage);
            let copied = sftp
                .sftp_upload(
                    &mut file,
                    &staging,
                    bytes,
                    progress,
                    &mut set_stage,
                    state.total_deadline,
                )
                .await?;
            state.set_stage(UploadStage::SftpMetadata);
            let staged_bytes = sftp_stage(
                "sftp_metadata",
                SFTP_IO_STAGE_DEADLINE,
                state.total_deadline,
                copied,
                bytes,
                sftp.sftp_metadata_size(&staging),
            )
            .await?;
            if staged_bytes != bytes {
                return Err(UploadFailure::before_publication(crate::invalid_config(
                    format!(
                        "SFTP upload staging size mismatch for {remote_path}: expected {bytes}, got {staged_bytes}"
                    ),
                )));
            }
            Ok(copied)
        }
        .await;

        let acknowledged = match &transfer {
            Ok(copied) => *copied,
            Err(_) => 0,
        };
        let transfer_failure_stage = state.stage_label();
        state.set_stage(UploadStage::SftpSessionClose);
        let finish = sftp_stage(
            "sftp_session_close",
            SFTP_IO_STAGE_DEADLINE,
            state.total_deadline,
            acknowledged,
            bytes,
            sftp.finish(),
        )
        .await;
        let copied = match transfer {
            Ok(copied) => copied,
            Err(error) => {
                return Err(self
                    .finish_failed_sftp_upload_cleanup(
                        &staging,
                        transfer_failure_stage,
                        error,
                        &mut staging_guard,
                        state,
                    )
                    .await);
            }
        };
        if let Err(error) = finish {
            return Err(self
                .finish_failed_sftp_upload_cleanup(
                    &staging,
                    UploadStage::SftpSessionClose.label(),
                    UploadFailure::before_publication(error),
                    &mut staging_guard,
                    state,
                )
                .await);
        }

        if let Some(expected_sha256) = expected_sha256 {
            state.set_stage(UploadStage::SftpHash);
            match sftp_stage(
                "agent_staging_sha256",
                AGENT_SHA256_RPC_DEADLINE,
                state.total_deadline,
                bytes,
                bytes,
                Box::pin(self.path_sha256(staging.clone())),
            )
            .await
            {
                Ok((actual_bytes, actual_sha256))
                    if actual_bytes == bytes && actual_sha256 == expected_sha256 => {}
                Ok((actual_bytes, actual_sha256)) => {
                    let failure = UploadFailure::before_publication(crate::invalid_config(
                        format!(
                            "SFTP upload staging integrity mismatch for {remote_path}: expected {bytes} bytes / {expected_sha256}, got {actual_bytes} bytes / {actual_sha256}"
                        ),
                    ));
                    return Err(self
                        .finish_failed_sftp_upload_cleanup(
                            &staging,
                            UploadStage::SftpHash.label(),
                            failure,
                            &mut staging_guard,
                            state,
                        )
                        .await);
                }
                Err(error) => {
                    return Err(self
                        .finish_failed_sftp_upload_cleanup(
                            &staging,
                            UploadStage::SftpHash.label(),
                            UploadFailure::before_publication(error),
                            &mut staging_guard,
                            state,
                        )
                        .await);
                }
            }
        }

        state.set_stage(UploadStage::Publication);
        // PathRename is an authenticated mutating Agent RPC, not SFTP I/O.
        // Preserve the overall TargetSsh transfer deadline and the
        // may-have-committed state instead of imposing SFTP's 30-second limit.
        let publication =
            Box::pin(self.publish_upload_staging(&staging, &destination, overwrite, state)).await;
        if let Err(error) = publication {
            return Err(self
                .finish_failed_sftp_upload_cleanup(
                    &staging,
                    UploadStage::Publication.label(),
                    error,
                    &mut staging_guard,
                    state,
                )
                .await);
        }
        staging_guard.disarm();
        Ok(Some(copied))
    }

    async fn remove_sftp_staging(
        &self,
        path: &str,
        total_deadline: tokio::time::Instant,
        state: &UploadProgressState,
    ) -> AppResult<()> {
        state.set_stage(UploadStage::SftpCleanup);
        let acknowledged = state.acknowledged_bytes.load(Ordering::Relaxed);
        let total = state.total_bytes.load(Ordering::Relaxed);
        sftp_stage(
            "staging_cleanup",
            REMOTE_STAGING_CLEANUP_DEADLINE,
            total_deadline,
            acknowledged,
            total,
            async {
                let Some(mut sftp) = self.open_sftp().await? else {
                    return Err(crate::invalid_config(
                        "target SSH SFTP subsystem became unavailable while cleaning upload staging"
                            .to_owned(),
                    ));
                };
                sftp.sftp_remove_file(path).await?;
                sftp.finish().await
            },
        )
        .await
    }

    async fn finish_failed_sftp_upload_cleanup(
        &self,
        staging: &str,
        cause_stage: &'static str,
        failure: UploadFailure,
        staging_guard: &mut RemoteStagingGuard,
        state: &UploadProgressState,
    ) -> UploadFailure {
        let cleanup = self
            .remove_sftp_staging(staging, state.total_deadline, state)
            .await;
        failure_after_staging_cleanup(failure, cause_stage, cleanup, staging_guard)
    }

    async fn publish_upload_staging(
        &self,
        staging: &str,
        destination: &str,
        overwrite: bool,
        state: &UploadProgressState,
    ) -> Result<(), UploadFailure> {
        let request = AgentRequest::new(
            self.server.secret()?,
            AgentRequestKind::PathRename {
                from: staging.to_owned(),
                to: destination.to_owned(),
                overwrite,
            },
        );
        let mut channel = self.open_channel().await?;
        state.publication_started.store(true, Ordering::Relaxed);
        write_request(&mut channel, &request)
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        channel
            .close_write()
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        let response = read_response_unbuffered(&mut channel)
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        if !response.ok {
            return Err(UploadFailure::before_publication(
                response_into_kind(response).expect_err("failed response is an error"),
            ));
        }
        match response_into_kind(response).map_err(UploadFailure::publication_may_have_committed)? {
            AgentResponseKind::PathRenamed => {}
            other => {
                return Err(UploadFailure::publication_may_have_committed(
                    crate::invalid_config(format!(
                        "remote agent returned unexpected upload publication response: {other:?}"
                    )),
                ));
            }
        }
        channel
            .finish()
            .await
            .map_err(UploadFailure::publication_may_have_committed)?;
        Ok(())
    }
}

#[cfg(test)]
mod deadline_regressions {
    use super::{AGENT_SHA256_RPC_DEADLINE, SFTP_IO_STAGE_DEADLINE, TARGET_SSH_UPLOAD_DEADLINE};

    #[test]
    fn agent_hash_rpc_has_independent_budget_from_sftp() {
        // Agent's authenticated PathSha256 RPC can outlast a single SFTP request.
        assert!(AGENT_SHA256_RPC_DEADLINE > SFTP_IO_STAGE_DEADLINE);
        // TargetSsh still has one earlier overall transfer deadline.
        assert!(AGENT_SHA256_RPC_DEADLINE <= TARGET_SSH_UPLOAD_DEADLINE);
    }
}

#[cfg(test)]
mod retry_safety_regressions {
    use super::{
        UploadFailure, UploadFailureStage, failure_after_staging_cleanup,
        should_retry_upload_failure,
    };
    use crate::AppError;
    use std::io;

    fn transient_failure() -> UploadFailure {
        UploadFailure::before_publication(AppError::new(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "connection reset during SFTP transfer",
        )))
    }

    fn mock_outer_attempt_counts(
        mut outcomes: Vec<Option<UploadFailure>>,
    ) -> (usize, usize, usize) {
        let mut attempts = 0;
        let mut sftp_creates = 0;
        let mut path_renames = 0;
        for attempt in 1..=super::FILE_TRANSFER_ATTEMPTS {
            attempts += 1;
            sftp_creates += 1;
            match outcomes.remove(0) {
                None => {
                    path_renames += 1;
                    return (attempts, sftp_creates, path_renames);
                }
                Some(failure) if should_retry_upload_failure(&failure, attempt) => {}
                Some(failure) => {
                    if failure.stage == UploadFailureStage::PublicationMayHaveCommitted {
                        path_renames += 1;
                    }
                    return (attempts, sftp_creates, path_renames);
                }
            }
        }
        (attempts, sftp_creates, path_renames)
    }

    #[test]
    fn confirmed_staging_removal_keeps_bounded_transient_retry() {
        let mut guard = super::RemoteStagingGuard::new(|| Box::pin(async {}));
        let failure =
            failure_after_staging_cleanup(transient_failure(), "sftp_write", Ok(()), &mut guard);

        assert_eq!(failure.stage, UploadFailureStage::BeforePublication);
        assert!(
            guard.cleanup.is_none(),
            "confirmed cleanup disarms the guard"
        );
        assert_eq!(
            mock_outer_attempt_counts(vec![Some(failure), None]),
            (2, 2, 1),
            "a transient pre-publication error with confirmed cleanup reaches the next upload attempt"
        );
    }

    #[test]
    fn unconfirmed_staging_cleanup_makes_transient_failure_terminal() {
        let mut guard = super::RemoteStagingGuard::new(|| Box::pin(async {}));
        let failure = failure_after_staging_cleanup(
            transient_failure(),
            "sftp_write",
            Err(crate::invalid_config(
                "cleanup transport refused at /private/credential/path".to_owned(),
            )),
            &mut guard,
        );

        assert_eq!(
            failure.stage,
            UploadFailureStage::BeforePublicationCleanupUnconfirmed
        );
        assert!(
            guard.cleanup.is_some(),
            "unconfirmed cleanup keeps the guard armed"
        );
        assert!(failure.error.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|source| source.kind() == io::ErrorKind::ConnectionReset)
        }));
        let diagnostic = format!("{:#}", failure.error);
        assert!(diagnostic.contains("cleanup=unconfirmed"));
        assert!(diagnostic.contains("cause_stage=sftp_write"));
        assert!(diagnostic.contains("cleanup_failure=transport"));
        assert!(!diagnostic.contains("/private/credential/path"));
        assert_eq!(
            mock_outer_attempt_counts(vec![Some(failure), None]),
            (1, 1, 0),
            "unconfirmed staging must not trigger another SFTP create or a PathRename"
        );
    }

    #[test]
    fn ambiguous_publication_remains_terminal_to_retry_classifier() {
        let failure = UploadFailure::publication_may_have_committed(crate::invalid_config(
            "publication response was lost".to_owned(),
        ));

        assert_eq!(
            mock_outer_attempt_counts(vec![Some(failure), None]),
            (1, 1, 1),
            "a possibly committed publication is never replayed by the retry loop"
        );
    }
}
