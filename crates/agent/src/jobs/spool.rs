use super::*;

pub(super) fn open_job_output(
    runtime: &JobRuntime,
    id: JobId,
    stream: JobOutput,
) -> io::Result<(tokio::fs::File, std::fs::File)> {
    let file = crate::jobs::open_output_append(&runtime.store.output_path(id, stream))?;
    let sync_file = file.try_clone()?;
    Ok((tokio::fs::File::from_std(file), sync_file))
}

pub(super) struct CappedOutputWriter {
    file: tokio::fs::File,
    written: u64,
    cancel: processkit::CancellationToken,
    ended: Arc<AtomicBool>,
}

impl CappedOutputWriter {
    pub(super) fn new(
        file: tokio::fs::File,
        written: u64,
        cancel: processkit::CancellationToken,
        ended: Arc<AtomicBool>,
    ) -> Self {
        Self {
            file,
            written,
            cancel,
            ended,
        }
    }
}

impl AsyncWrite for CappedOutputWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.ended.store(false, Ordering::Release);
        let remaining = crate::jobs::MAX_JOB_OUTPUT_BYTES.saturating_sub(self.written) as usize;
        if remaining == 0 && !buffer.is_empty() {
            self.cancel.cancel();
            // Cancel the tree, but keep draining to the pump's EOF flush.
            // Returning Err makes ProcessKit disable the tee without flushing it.
            return Poll::Ready(Ok(buffer.len()));
        }
        let allowed = buffer.len().min(remaining);
        match Pin::new(&mut self.file).poll_write(cx, &buffer[..allowed]) {
            Poll::Ready(Ok(written)) => {
                self.written += written as u64;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.cancel.cancel();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.file).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            // ProcessKit 3.3.4 pump.rs flushes this private tee only at stream end.
            self.ended.store(true, Ordering::Release);
        } else if matches!(result, Poll::Ready(Err(_))) {
            self.cancel.cancel();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.file).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            self.cancel.cancel();
        }
        result
    }
}
