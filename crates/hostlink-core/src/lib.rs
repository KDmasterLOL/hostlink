//! Small runtime-neutral primitives shared by HostLink crates.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod bounded_log;
mod correlation;
mod digest;
pub mod filesystem;
mod host;
mod json_file;
mod json_lines;
mod lock_file;
mod process;
mod redaction;
mod secret;
mod stream_io;
mod time;

pub use bounded_log::{RetainedLog, RetainedLogTail, RetainedLogWriter};
pub use correlation::{
    ONEC_EXEC_DEADLINE_UNIX_MS_ENV, ONEC_JOB_ID_ENV, ONEC_JOB_SYSTEM_ENV, ONEC_PARENT_RUN_ID_ENV,
    ONEC_RESULT_DIR_ENV,
};
pub use digest::Sha256Digest;
pub use filesystem::*;
pub use host::{
    HostResolutionDiagnostic, host_resolution_diagnostic, normalize_hostname, system_hostname,
};
pub use json_file::{read_json_file_bounded, write_new_json_file};
pub use json_lines::{append_json_line, read_line_bounded};
pub use json_lines::{read_json_line_bounded, write_json_line};
pub use lock_file::acquire_exclusive_file_lock;
pub use process::{
    DEFAULT_PROCESS_CAPTURE_BYTES, OwnedProcess, background_command,
    configure_background_process_with_flags, windows_command_line,
};
pub use redaction::RedactingWriter;
pub use secret::{constant_time_eq, constant_time_str_eq};
pub use stream_io::{BoundedTail, read_bounded_bytes, read_stream_tail_bounded};
pub use time::unix_time_ms;

#[cfg(test)]
mod tests;
