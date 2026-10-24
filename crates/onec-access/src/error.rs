//! Application error boundary for controller-side hub/access operations.
//!
//! Generic propagation and context use `anyhow`. Only process failures remain typed because
//! retry/transport policy branches on their semantics.

use hostlink_core::PrivatePathError;
use std::{io, path::PathBuf};

/// Application error type for controller-side hub/access operations.
pub type AppError = anyhow::Error;
/// Result type for controller-side hub/access operations.
pub type AppResult<T> = anyhow::Result<T>;

/// Typed process failure retained where transport/retry policy needs structured semantics.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// Child process could not be started.
    #[error("failed to start {program} for {operation}: {source}")]
    Start {
        /// Executable that failed to start.
        program: PathBuf,
        /// Human-readable operation label.
        operation: String,
        /// Underlying process-spawn failure.
        #[source]
        source: io::Error,
    },
    /// Child process exited unsuccessfully.
    #[error("{operation} via {program} exited with {code:?}: {details}")]
    Failed {
        /// Executable that was invoked.
        program: PathBuf,
        /// Human-readable operation label.
        operation: String,
        /// Exit code when supplied by the operating system.
        code: Option<i32>,
        /// Bounded/redacted failure details.
        details: String,
    },
    /// Child process exceeded its deadline and its owned tree was terminated.
    #[error(
        "{operation} via {program} timed out after {timeout_ms} ms (PID {pid}, code {code:?}): {details}"
    )]
    Timeout {
        /// Executable that exceeded the deadline.
        program: PathBuf,
        /// Human-readable operation label.
        operation: String,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
        /// Root process identifier.
        pid: u32,
        /// Exit code observed during termination/reaping, when available.
        code: Option<i32>,
        /// Bounded/redacted timeout details.
        details: String,
    },
}

fn contextual_source<E>(source: E, context: impl Into<String>) -> AppError
where
    E: std::error::Error + Send + Sync + 'static,
{
    let context = context.into();
    let details = source.to_string();
    AppError::new(source).context(format!("{context}: {details}"))
}

pub(crate) fn io_error(path: impl Into<PathBuf>, source: io::Error) -> AppError {
    let path = path.into();
    contextual_source(source, format!("I/O error at {}", path.display()))
}

pub(crate) fn private_path_error(error: PrivatePathError) -> AppError {
    match error {
        PrivatePathError::Io { path, source } => io_error(path, source),
        PrivatePathError::Invalid(message) => invalid_config(message),
    }
}

pub(crate) fn json_error(path: impl Into<PathBuf>, source: serde_json::Error) -> AppError {
    let path = path.into();
    contextual_source(source, format!("invalid JSON at {}", path.display()))
}

pub(crate) fn protocol_io_error(operation: impl Into<String>, source: io::Error) -> AppError {
    contextual_source(source, operation)
}

pub(crate) fn protocol_json_error(
    operation: impl Into<String>,
    source: serde_json::Error,
) -> AppError {
    contextual_source(source, operation)
}

pub(crate) fn protocol_error(message: impl Into<String>) -> AppError {
    anyhow::anyhow!(message.into())
}

/// Creates the stable invalid-controller-configuration error used by the library and CLI.
pub fn invalid_config(message: impl Into<String>) -> AppError {
    anyhow::anyhow!("invalid hostlink configuration: {}", message.into())
}

/// Creates the stable hub/access object-not-found error used by the library and CLI.
pub fn not_found_error(message: impl Into<String>) -> AppError {
    anyhow::anyhow!("hostlink object not found: {}", message.into())
}

pub(crate) fn http_error(message: impl Into<String>) -> AppError {
    anyhow::anyhow!("network request failed: {}", message.into())
}

pub(crate) fn process_start_error(
    program: PathBuf,
    operation: String,
    source: io::Error,
) -> AppError {
    ProcessError::Start {
        program,
        operation,
        source,
    }
    .into()
}

/// Creates a typed non-zero child-process error used by the library and CLI.
pub fn process_failed_error(
    program: PathBuf,
    operation: String,
    code: Option<i32>,
    details: String,
) -> AppError {
    ProcessError::Failed {
        program,
        operation,
        code,
        details,
    }
    .into()
}

pub(crate) fn remote_transport_error(
    host: impl Into<String>,
    phase: impl Into<String>,
    source: AppError,
) -> AppError {
    let host = host.into();
    let phase = phase.into();
    let details = source.to_string();
    source.context(format!(
        "hub-target-ssh transport to {host} failed while {phase}: {details}; target onec-agent state is unknown until the SSH transport succeeds"
    ))
}

pub(crate) fn protocol_io<T>(operation: impl Into<String>, result: io::Result<T>) -> AppResult<T> {
    let operation = operation.into();
    result.map_err(|source| protocol_io_error(operation, source))
}

pub(crate) fn protocol_json<T>(
    operation: impl Into<String>,
    result: serde_json::Result<T>,
) -> AppResult<T> {
    let operation = operation.into();
    result.map_err(|source| protocol_json_error(operation, source))
}
