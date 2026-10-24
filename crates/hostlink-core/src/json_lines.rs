//! Bounded JSON Lines framing for control protocols.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, BufRead, Write};

/// Serialize one value as compact JSON, append a newline, and flush the writer.
pub fn write_json_line<T: Serialize + ?Sized>(mut writer: impl Write, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Read and deserialize one newline-delimited JSON value with an explicit byte bound.
///
/// The bound includes the newline when present. EOF before any bytes is reported as
/// [`io::ErrorKind::UnexpectedEof`].
///
/// # Errors
///
/// Returns an I/O error when reading fails, the record exceeds `max_line_bytes`, input ends
/// before a record starts, or the record is not valid JSON for `T`.
pub fn read_json_line_bounded<T: DeserializeOwned>(
    mut reader: impl BufRead,
    max_line_bytes: usize,
) -> io::Result<T> {
    let line = read_line_bounded(&mut reader, max_line_bytes)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "input closed before a JSON line",
        )
    })?;
    serde_json::from_slice(&line).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_line_bounded(
    reader: &mut impl BufRead,
    max_line_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    if max_line_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "line byte limit must be greater than zero",
        ));
    }

    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(take) > max_line_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "line exceeds maximum size",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Ok(Some(line))
}
