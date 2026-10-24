//! Verified file-transfer lifecycle.

mod download;
mod result;
mod upload;

#[cfg(test)]
mod cancellation_tests;

use crate::AppError;
use std::fs;
use std::future::Future;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub(super) const FILE_TRANSFER_SHA256_CAPABILITY: &str = "file-sha256-v1";
pub(super) const FILE_TRANSFER_ATTEMPTS: usize = 3;
pub(super) const SFTP_IO_STAGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const TRANSFER_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(in crate::remote) enum UploadStage {
    Preflight,
    SftpOpen,
    SftpDestinationCheck,
    SftpFileOpen,
    SftpWrite,
    SftpSync,
    SftpClose,
    SftpSessionClose,
    SftpCleanup,
    SftpMetadata,
    SftpHash,
    Publication,
    FinalVerification,
    AgentTransfer,
}

impl UploadStage {
    pub(in crate::remote) fn label(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::SftpOpen => "sftp_open",
            Self::SftpDestinationCheck => "sftp_destination_check",
            Self::SftpFileOpen => "sftp_file_open",
            Self::SftpWrite => "sftp_write",
            Self::SftpSync => "sftp_sync",
            Self::SftpClose => "sftp_close",
            Self::SftpSessionClose => "sftp_session_close",
            Self::SftpCleanup => "staging_cleanup",
            Self::SftpMetadata => "sftp_metadata",
            Self::SftpHash => "sftp_hash",
            Self::Publication => "publish",
            Self::FinalVerification => "final_verification",
            Self::AgentTransfer => "agent_transfer",
        }
    }
}

/// Bound one remote SFTP request by its stage budget even after total time has elapsed.
/// The TargetSsh owner separately enforces the earlier overall transfer deadline; cleanup
/// and other carriers must not become unbounded if that deadline is already past.
pub(in crate::remote) async fn sftp_stage<T, E>(
    stage: &'static str,
    stage_budget: std::time::Duration,
    _total_deadline: tokio::time::Instant,
    acknowledged_bytes: u64,
    total_bytes: u64,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<AppError>,
{
    let started = tokio::time::Instant::now();
    let stage_deadline = started + stage_budget;
    match tokio::time::timeout_at(stage_deadline, operation).await {
        Ok(result) => result,
        Err(_) => {
            let elapsed_ms = started.elapsed().as_millis();
            Err(sftp_stage_timeout_error(stage, elapsed_ms, acknowledged_bytes, total_bytes).into())
        }
    }
}

pub(in crate::remote) fn sftp_stage_timeout_error(
    stage: &'static str,
    elapsed_ms: u128,
    acknowledged_bytes: u64,
    total_bytes: u64,
) -> AppError {
    // The diagnostic key is retained for compatibility; this count is client-side write progress,
    // not proof of remote acknowledgement, publication, or cleanup.
    let diagnostic = format!(
        "phase=stage_deadline stage={stage} elapsed_ms={elapsed_ms} acknowledged_bytes={acknowledged_bytes}/{total_bytes} remote_state=unknown"
    );
    let _ = writeln!(
        std::io::stderr().lock(),
        "hostlink upload outcome: {diagnostic}"
    );
    crate::invalid_config(format!(
        "target SSH upload stage deadline exceeded ({diagnostic})"
    ))
}

/// Owns a local transfer staging path until it is atomically published.
///
/// Drop only schedules cleanup on the already-running Tokio runtime; it never performs blocking
/// filesystem I/O or creates a runtime of its own.
pub(super) struct LocalTempGuard {
    path: PathBuf,
    armed: bool,
}

impl LocalTempGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(super) async fn cleanup_best_effort(&mut self) {
        let _ = tokio::fs::remove_file(&self.path).await;
        self.disarm();
    }
}

impl Drop for LocalTempGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let path = self.path.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(move || {
                let _ = fs::remove_file(path);
            });
        }
    }
}

type RemoteCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Schedules cleanup for an upload staging file when its async owner is cancelled.
pub(super) struct RemoteStagingGuard {
    cleanup: Option<Box<dyn FnOnce() -> RemoteCleanupFuture + Send + 'static>>,
    diagnostic: Option<Box<dyn Fn() -> String + Send + 'static>>,
}

impl RemoteStagingGuard {
    pub(super) fn new(cleanup: impl FnOnce() -> RemoteCleanupFuture + Send + 'static) -> Self {
        Self {
            cleanup: Some(Box::new(cleanup)),
            diagnostic: None,
        }
    }

    pub(super) fn with_diagnostic(
        mut self,
        diagnostic: impl Fn() -> String + Send + 'static,
    ) -> Self {
        self.diagnostic = Some(Box::new(diagnostic));
        self
    }

    pub(super) fn disarm(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for RemoteStagingGuard {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        let diagnostic = self
            .diagnostic
            .take()
            .map_or_else(|| "state=unconfirmed".to_owned(), |format| format());
        let _ = writeln!(
            std::io::stderr().lock(),
            "hostlink remote staging cleanup: {diagnostic}"
        );
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup());
        }
    }
}

pub(super) fn create_local_temp_file(
    path: PathBuf,
) -> crate::AppResult<(LocalTempGuard, tokio::fs::File)> {
    // Create synchronously so ownership is established before the next cancellation point.
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| crate::io_error(&path, source))?;
    let guard = LocalTempGuard::new(path);
    Ok((guard, tokio::fs::File::from_std(file)))
}

pub(super) async fn sha256_file_async(path: &Path) -> crate::AppResult<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::sha256_file(&path))
        .await
        .map_err(|error| crate::invalid_config(format!("SHA-256 worker failed: {error}")))?
}

pub(super) async fn copy_exact_with_progress<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    total: u64,
    progress: &mut F,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(u64, u64),
{
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; TRANSFER_BUFFER_BYTES];
    while copied < total {
        let remaining = usize::try_from((total - copied).min(buffer.len() as u64))
            .expect("bounded transfer chunk length");
        let read = reader.read(&mut buffer[..remaining]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("transfer ended after {copied} of {total} bytes"),
            ));
        }
        writer.write_all(&buffer[..read]).await?;
        copied += read as u64;
        progress(copied, total);
    }
    Ok(copied)
}

pub(super) fn sftp_path(path: &str) -> String {
    path.replace('\\', "/")
}

pub(super) fn sftp_staging_path(destination: &str) -> crate::AppResult<String> {
    let destination = sftp_path(destination);
    let (parent, name) = match destination.rsplit_once('/') {
        Some((parent, name)) => (Some(parent), name),
        None => (None, destination.as_str()),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(crate::invalid_config(format!(
            "SFTP upload destination must name a file: {destination:?}"
        )));
    }
    let staging = format!(".{name}.onec-upload-{}.tmp", Uuid::new_v4().simple());
    Ok(match parent {
        Some(parent) if !parent.is_empty() => format!("{parent}/{staging}"),
        Some(_) if destination.starts_with('/') => format!("/{staging}"),
        _ => staging,
    })
}

pub(super) fn is_transient_transfer_error(error: &AppError) -> bool {
    if let Some(source) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        && matches!(
            source.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::UnexpectedEof
        )
    {
        return true;
    }

    if let Some(process) = error.downcast_ref::<crate::ProcessError>() {
        match process {
            crate::ProcessError::Timeout { .. } => return false,
            crate::ProcessError::Failed { details, .. } => {
                return has_transient_signature(details);
            }
            crate::ProcessError::Start { .. } => {}
        }
    }

    has_transient_signature(&error.to_string())
}

fn has_transient_signature(details: &str) -> bool {
    let details = details.to_ascii_lowercase();
    [
        "broken pipe",
        "connection reset",
        "connection refused",
        "connection closed",
        "closed before a response",
        "failed reading agent response",
        "unexpected eof",
    ]
    .iter()
    .any(|needle| details.contains(needle))
}

#[cfg(test)]
mod deadline_tests {
    use super::{is_transient_transfer_error, sftp_stage};
    use crate::AppError;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn never_ending_sftp_write_is_cancelled_with_sanitized_stage_diagnostics() {
        let total_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let dropped = Arc::new(AtomicBool::new(false));
        let marker = DropMarker(Arc::clone(&dropped));
        let error = sftp_stage(
            "sftp_write",
            Duration::from_millis(10),
            total_deadline,
            64,
            128,
            async move {
                let _marker = marker;
                std::future::pending::<Result<(), AppError>>().await
            },
        )
        .await
        .expect_err("a stalled SFTP request must respect its own stage deadline");

        let rendered = error.to_string();
        assert!(rendered.contains("phase=stage_deadline"), "{rendered}");
        assert!(rendered.contains("stage=sftp_write"), "{rendered}");
        assert!(rendered.contains("elapsed_ms="), "{rendered}");
        assert!(rendered.contains("acknowledged_bytes=64/128"), "{rendered}");
        // Check the sanitized stage details, not the fixed HostLink product prefix.
        let details = rendered
            .strip_prefix("invalid hostlink configuration: ")
            .expect("stable error context");
        assert!(!details.contains("host"), "{rendered}");
        assert!(!details.contains("path"), "{rendered}");
        assert!(
            dropped.load(Ordering::Acquire),
            "the stalled request is cancelled"
        );
    }

    #[tokio::test]
    async fn slow_mock_sftp_write_times_out_once_without_retry_authority() {
        let total_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let mut terminal_error = None;
        for _ in 0..super::FILE_TRANSFER_ATTEMPTS {
            attempts.fetch_add(1, Ordering::SeqCst);
            match sftp_stage(
                "sftp_write",
                Duration::from_millis(10),
                total_deadline,
                11_862_016,
                28_182_528,
                std::future::pending::<Result<(), AppError>>(),
            )
            .await
            {
                Ok(()) => break,
                Err(error) if is_transient_transfer_error(&error) => continue,
                Err(error) => {
                    terminal_error = Some(error);
                    break;
                }
            }
        }
        let error = terminal_error.expect("the simulated SFTP write must fail closed");

        assert!(error.to_string().contains("stage=sftp_write"));
        assert!(
            error
                .to_string()
                .contains("acknowledged_bytes=11862016/28182528")
        );
        assert!(
            !is_transient_transfer_error(&error),
            "a stage deadline does not trigger upload retry"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn expired_total_budget_does_not_disable_stage_timeout_for_cleanup() {
        let expired_total = tokio::time::Instant::now() - Duration::from_secs(1);
        let error = sftp_stage(
            "staging_cleanup",
            Duration::from_millis(10),
            expired_total,
            0,
            1,
            std::future::pending::<crate::AppResult<()>>(),
        )
        .await
        .expect_err("cleanup still needs a bounded stage deadline");
        assert!(error.to_string().contains("stage=staging_cleanup"));
    }

    #[tokio::test]
    async fn total_deadline_remains_the_owner_when_it_precedes_stage_deadline() {
        let total_deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let outcome = tokio::time::timeout_at(
            total_deadline,
            sftp_stage(
                "sftp_write",
                Duration::from_secs(1),
                total_deadline,
                0,
                1,
                std::future::pending::<Result<(), AppError>>(),
            ),
        )
        .await;

        assert!(
            outcome.is_err(),
            "the enclosing total budget owns cancellation"
        );
    }
}
