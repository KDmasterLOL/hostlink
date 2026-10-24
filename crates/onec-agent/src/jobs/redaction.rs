//! Agent secret-pattern policy and child-output redaction orchestration.

use super::*;
use std::sync::{Arc, Mutex};

pub(super) fn secret_patterns(secret_env: &SecretEnvironment) -> Vec<Vec<u8>> {
    secret_env
        .values()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

/// Fail-visible durable byte sink applied before bounded log storage.
pub(super) struct DurableJobLogSink {
    writer: Option<RedactingWriter<onec_core::RetainedLogWriter>>,
}

impl DurableJobLogSink {
    /// Open one bounded durable log and configure its secret patterns.
    pub(super) fn open(path: &Path, patterns: Vec<Vec<u8>>) -> io::Result<Self> {
        let file = RetainedLog::new(path)?.writer(JOB_LOG_SEGMENT_BYTES)?;
        let writer = RedactingWriter::new(file, patterns)?;
        Ok(Self {
            writer: Some(writer),
        })
    }

    /// Redact and append one exact raw child-output chunk.
    pub(super) fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer
            .as_mut()
            .ok_or_else(|| io::Error::other("durable job log sink was already finalized"))?
            .push(bytes)
    }

    /// Flush redaction state and synchronize the final bounded segment.
    pub(super) fn finish(&mut self) -> io::Result<()> {
        let writer = self
            .writer
            .take()
            .ok_or_else(|| io::Error::other("durable job log sink was already finalized"))?;
        let mut file = writer.finish()?;
        file.sync_all()
    }
}

/// ProcessKit adapter that keeps synchronous bounded-log I/O off the async pump runtime.
pub(super) struct ProcesskitDurableJobLogSink {
    state: Arc<Mutex<LazyDurableJobLogSink>>,
}

/// Lazily opens the durable log so factory creation itself stays infallible.
struct LazyDurableJobLogSink {
    path: PathBuf,
    patterns: Vec<Vec<u8>>,
    sink: Option<DurableJobLogSink>,
    finished: bool,
}

impl ProcesskitDurableJobLogSink {
    /// Creates one independent lazy sink for a ProcessKit pump.
    pub(super) fn new(path: PathBuf, patterns: Vec<Vec<u8>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(LazyDurableJobLogSink {
                path,
                patterns,
                sink: None,
                finished: false,
            })),
        }
    }
}

impl LazyDurableJobLogSink {
    /// Returns the opened sink, creating it on the first write or finalization.
    fn sink(&mut self) -> io::Result<&mut DurableJobLogSink> {
        if self.finished {
            return Err(io::Error::other(
                "durable job log sink was already finalized",
            ));
        }
        if self.sink.is_none() {
            self.sink = Some(DurableJobLogSink::open(&self.path, self.patterns.clone())?);
        }
        self.sink
            .as_mut()
            .ok_or_else(|| io::Error::other("durable job log sink was not initialized"))
    }

    /// Writes one raw chunk through the redactor and bounded-log writer.
    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.sink()?.write_chunk(bytes)
    }

    /// Finalizes redaction and synchronizes the durable log exactly once.
    fn finish(&mut self) -> io::Result<()> {
        self.sink()?.finish()?;
        self.finished = true;
        Ok(())
    }
}

impl processkit::RawOutputSink for ProcesskitDurableJobLogSink {
    fn write_chunk<'a>(&'a mut self, chunk: &'a [u8]) -> processkit::RawSinkFuture<'a> {
        let state = Arc::clone(&self.state);
        let chunk = chunk.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut state = state
                    .lock()
                    .map_err(|_| io::Error::other("durable job log sink lock poisoned"))?;
                state.write_chunk(&chunk)
            })
            .await
            .map_err(|_| io::Error::other("durable job log writer task panicked"))?
        })
    }

    fn finish(&mut self) -> processkit::RawSinkFuture<'_> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut state = state
                    .lock()
                    .map_err(|_| io::Error::other("durable job log sink lock poisoned"))?;
                state.finish()
            })
            .await
            .map_err(|_| io::Error::other("durable job log writer task panicked"))?
        })
    }
}
