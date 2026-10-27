#![allow(unused_imports)]
use super::config::invalid_data;
use super::*;

pub(super) struct JobRuntime {
    pub(super) store: JobStore,
    pub(super) start_lock: Mutex<()>,
    pub(super) slots: Arc<Semaphore>,
    pub(super) channel_slots: Arc<Semaphore>,
    pub(super) accepting: AtomicBool,
    pub(super) shutdown: processkit::CancellationToken,
    pub(super) active_jobs: std::sync::Mutex<HashMap<JobId, Arc<JobCancellation>>>,
}

/// Process cancellation is Agent-owned and unrelated to SSH channel lifetimes.
pub(super) struct JobCancellation {
    pub(super) process: processkit::CancellationToken,
    pub(super) requested: AtomicBool,
}

/// Serves authenticated SSH/SFTP traffic on the configured loopback listener until shutdown.
pub(super) fn verify_job_source(spec: &JobSpec) -> io::Result<PathBuf> {
    if !Path::new(&spec.program).is_absolute() || spec.program.contains('\0') {
        return Err(invalid_data("job executable must be an absolute path"));
    }
    let program = Path::new(&spec.program);
    let metadata = std::fs::symlink_metadata(program)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            "job executable must be a regular non-symlink file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid_data("job executable must not be a reparse point"));
        }
        if !crate::exec::safe_windows_user_context()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable jobs require a verified non-elevated, non-LocalSystem Windows user context",
            ));
        }
        jobs::validate_private_path(program, false)?;
        if let Some(parent) = program.parent() {
            jobs::validate_private_path(parent, true)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid_data("job executable has no execute permission"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(program)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(invalid_data("job executable must be a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_size() != opened_metadata.file_size()
            || metadata.last_write_time() != opened_metadata.last_write_time()
            || metadata.creation_time() != opened_metadata.creation_time()
        {
            return Err(invalid_data(
                "job executable path changed while opening for verification",
            ));
        }
    }
    #[cfg(windows)]
    let original_identity = windows_file_identity(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened_metadata.uid() != unsafe { libc::geteuid() }
            || opened_metadata.nlink() != 1
            || opened_metadata.permissions().mode() & 0o222 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "job executable must be Agent-owned, singly linked and read-only",
            ));
        }
    }
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest_writer(&mut digest))?;
    if format!("{:x}", digest.finalize()) != spec.source_sha256 {
        return Err(invalid_data("job executable digest mismatch"));
    }
    let after_hash = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if after_hash.dev() != opened_metadata.dev()
            || after_hash.ino() != opened_metadata.ino()
            || after_hash.len() != opened_metadata.len()
            || after_hash.mtime() != opened_metadata.mtime()
            || after_hash.mtime_nsec() != opened_metadata.mtime_nsec()
            || after_hash.ctime() != opened_metadata.ctime()
            || after_hash.ctime_nsec() != opened_metadata.ctime_nsec()
            || path_after_hash.file_type().is_symlink()
            || path_after_hash.dev() != opened_metadata.dev()
            || path_after_hash.ino() != opened_metadata.ino()
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let path_after_hash = std::fs::symlink_metadata(program)?;
        if path_after_hash.file_attributes() & 0x400 != 0
            || after_hash.file_size() != opened_metadata.file_size()
            || after_hash.last_write_time() != opened_metadata.last_write_time()
            || path_after_hash.file_size() != opened_metadata.file_size()
            || path_after_hash.last_write_time() != opened_metadata.last_write_time()
            || original_identity != windows_file_identity(&file)?
            || original_identity != windows_file_identity(&std::fs::File::open(program)?)?
        {
            return Err(invalid_data(
                "job executable changed during source verification",
            ));
        }
    }
    // The open descriptor is hashed, then ProcessKit launches by pathname. Read-only ownership
    // checks reduce external mutation, but cannot pin the executed inode against a same-UID path
    // replacement between this check and exec; this is not an exec-by-fd guarantee.
    if let Some(cwd) = &spec.cwd {
        let metadata = std::fs::symlink_metadata(cwd)?;
        if !cwd.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid_data(
                "job working directory must be absolute and safe",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid_data("job working directory is a reparse point"));
            }
            jobs::validate_private_path(cwd, true)?;
        }
    }
    Ok(program.to_path_buf())
}

/// Stable Win32 replacement for nightly-only MetadataExt file_index and
/// volume_serial_number. GetFileInformationByHandle is present on NT6.1.
#[cfg(windows)]
fn windows_file_identity(file: &std::fs::File) -> io::Result<(u32, u64, u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is an open, owned File handle, and info points to a
    // correctly sized writable Win32 output structure.
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    let write_time = (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
        | u64::from(info.ftLastWriteTime.dwLowDateTime);
    // Ambiguous file identity or multiple hardlinks cannot establish
    // that this source is the single privately controlled executable.
    if index == 0 || info.nNumberOfLinks != 1 {
        return Err(invalid_data(
            "source-pinned Windows executable identity is ambiguous or multiply linked",
        ));
    }
    Ok((info.dwVolumeSerialNumber, index, size, write_time))
}

fn digest_writer<'a>(digest: &'a mut Sha256) -> impl io::Write + 'a {
    struct DigestWriter<'a>(&'a mut Sha256);
    impl io::Write for DigestWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    DigestWriter(digest)
}

pub(super) async fn run_job(
    runtime: Arc<JobRuntime>,
    owner: String,
    record: crate::jobs::JobRecord,
    active: Arc<JobCancellation>,
) {
    let id = record.id;
    if verify_job_source(&record.spec).is_err() {
        let _ = runtime
            .store
            .transition(id, &owner, JobState::Running, JobState::Failed);
        return;
    }
    let (out, out_sync) = match open_job_output(&runtime, id, JobOutput::Stdout) {
        Ok(files) => files,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let (err, err_sync) = match open_job_output(&runtime, id, JobOutput::Stderr) {
        Ok(files) => files,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let overflowed = Arc::new(AtomicBool::new(false));
    let cancel = active.process.clone();
    let mut command = processkit::Command::new(&record.spec.program)
        .args(&record.spec.args)
        .stdin(processkit::Stdin::empty())
        .stdout_raw_tee(CappedOutputWriter::new(
            out,
            overflowed.clone(),
            cancel.clone(),
        ))
        .stderr_raw_tee(CappedOutputWriter::new(
            err,
            overflowed.clone(),
            cancel.clone(),
        ))
        .output_buffer(processkit::OutputBufferPolicy::bounded(256).with_max_bytes(64 * 1024))
        .timeout(JOB_TIMEOUT)
        .timeout_grace(Duration::from_secs(2))
        .kill_on_parent_death()
        .cancel_on(cancel);
    if let Some(cwd) = &record.spec.cwd {
        command = command.current_dir(cwd);
    }
    // ProcessKit owns timeout, cancellation and child cleanup. Windows uses its Job Object,
    // including kill-on-close for the complete process tree; Linux uses its private process group.
    let outcome = match command.start().await {
        Ok(child) => child.drain().await,
        Err(_) => {
            let _ = runtime
                .store
                .transition(id, &owner, JobState::Running, JobState::Failed);
            return;
        }
    };
    let sync_results =
        tokio::task::spawn_blocking(move || (out_sync.sync_all(), err_sync.sync_all())).await;
    let overflow = overflowed.load(Ordering::Acquire);
    let next = if runtime.shutdown.is_cancelled() {
        JobState::Interrupted
    } else if overflow
        || sync_results.is_err()
        || sync_results.is_ok_and(|(out, err)| out.is_err() || err.is_err())
    {
        JobState::Failed
    } else if active.requested.load(Ordering::Acquire) {
        // ProcessKit completed its child/tree drain. A verified cancellation is
        // terminal non-success; unlike uncertain crash interruption it must not
        // keep the Agent updater blocked forever.
        match outcome {
            Ok(_) => JobState::Failed,
            Err(error) if matches!(error.reason(), processkit::ErrorReason::Cancelled { .. }) => {
                // ProcessKit confirms full-tree teardown for Cancelled; only a
                // Teardown/error with uncertain surviving processes stays blocked.
                JobState::Failed
            }
            Err(_) => JobState::Interrupted,
        }
    } else {
        match outcome {
            Ok(processkit::Outcome::Exited(code)) => JobState::Exited { code },
            Ok(
                processkit::Outcome::Signalled(_)
                | processkit::Outcome::TimedOut
                | processkit::Outcome::InactivityTimedOut,
            ) => JobState::Failed,
            Err(_) => JobState::Failed,
            _ => JobState::Failed,
        }
    };
    let _ = runtime
        .store
        .transition(id, &owner, JobState::Running, next);
}

fn open_job_output(
    runtime: &JobRuntime,
    id: JobId,
    stream: JobOutput,
) -> io::Result<(tokio::fs::File, std::fs::File)> {
    let file = jobs::open_output_append(&runtime.store.output_path(id, stream))?;
    let sync_file = file.try_clone()?;
    Ok((tokio::fs::File::from_std(file), sync_file))
}

struct CappedOutputWriter {
    file: tokio::fs::File,
    written: u64,
    overflowed: Arc<AtomicBool>,
    cancel: processkit::CancellationToken,
}

impl CappedOutputWriter {
    fn new(
        file: tokio::fs::File,
        overflowed: Arc<AtomicBool>,
        cancel: processkit::CancellationToken,
    ) -> Self {
        Self {
            file,
            written: 0,
            overflowed,
            cancel,
        }
    }
}

impl AsyncWrite for CappedOutputWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let remaining = jobs::MAX_JOB_OUTPUT_BYTES.saturating_sub(self.written) as usize;
        if remaining == 0 && !buffer.is_empty() {
            self.overflowed.store(true, Ordering::Release);
            self.cancel.cancel();
            return Poll::Ready(Err(io::Error::other("job output exceeds 8 MiB limit")));
        }
        let allowed = buffer.len().min(remaining);
        match Pin::new(&mut self.file).poll_write(cx, &buffer[..allowed]) {
            Poll::Ready(Ok(written)) => {
                self.written += written as u64;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}
