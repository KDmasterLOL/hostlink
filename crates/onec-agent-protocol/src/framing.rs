//! Agent control protocol JSON Lines compatibility surface.

use crate::MAX_CONTROL_LINE_BYTES;
use serde::Deserialize;
use std::io::{self, BufRead};

pub use onec_core::write_json_line;

/// Reads and deserializes one bounded JSONL control-protocol record.
///
/// # Errors
///
/// Returns [`std::io::Error`] when the line exceeds [`crate::MAX_CONTROL_LINE_BYTES`], I/O fails,
/// or JSON does not decode into `T`.
pub fn read_json_line<T: for<'de> Deserialize<'de>>(reader: impl BufRead) -> io::Result<T> {
    onec_core::read_json_line_bounded(reader, MAX_CONTROL_LINE_BYTES)
}
