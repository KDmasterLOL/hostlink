//! JSON Lines framing and append-only JSONL file persistence.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Serialize one value as compact JSON, append a newline, and flush the writer.
pub fn write_json_line<T: Serialize + ?Sized>(mut writer: impl Write, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Read and deserialize one newline-delimited JSON value with an explicit byte bound.
///
/// The bound includes the newline when present. EOF before any bytes is reported as
/// io::ErrorKind::UnexpectedEof.
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

/// Read one newline-delimited record without allowing one line to allocate beyond `max_line_bytes`.
///
/// The byte bound includes the line terminator when present. The returned bytes omit CR/LF.
/// Clean EOF before any bytes returns `Ok(None)`; an empty line returns `Ok(Some(Vec::new()))`.
pub fn read_line_bounded(
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

/// Serialize one value as compact JSON and append it as exactly one newline-terminated record.
pub fn append_json_line<T: Serialize + ?Sized>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    write_json_line(file, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::io::BufReader;

    #[derive(Serialize)]
    struct Record<'a> {
        value: &'a str,
    }

    #[test]
    fn stream_json_line_round_trips() {
        let expected = Record {
            value: "первый"
        };
        let mut bytes = Vec::new();

        write_json_line(&mut bytes, &expected).expect("write");
        let actual: serde_json::Value =
            read_json_line_bounded(BufReader::new(bytes.as_slice()), 1024).expect("read");

        assert_eq!(actual["value"], "первый");
    }

    #[test]
    fn bounded_reader_rejects_oversized_line() {
        let bytes = vec![b'x'; 17];
        let error =
            read_json_line_bounded::<serde_json::Value>(BufReader::new(bytes.as_slice()), 16)
                .expect_err("oversized line");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn regression_inv_104_raw_line_reader_streams_and_bounds_each_record() {
        let bytes = b"first\r\n\nthird";
        let mut reader = BufReader::new(bytes.as_slice());
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(
            read_line_bounded(&mut reader, 16).unwrap(),
            Some(b"third".to_vec())
        );
        assert_eq!(read_line_bounded(&mut reader, 16).unwrap(), None);

        let oversized_bytes = vec![b'x'; 17];
        let mut oversized = BufReader::new(oversized_bytes.as_slice());
        assert_eq!(
            read_line_bounded(&mut oversized, 16).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn appends_one_compact_json_record_per_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("events.jsonl");

        append_json_line(
            &path,
            &Record {
                value: "первый"
            },
        )
        .expect("first");
        append_json_line(&path, &Record { value: "second" }).expect("second");

        assert_eq!(
            fs::read_to_string(path).expect("read"),
            "{\"value\":\"первый\"}\n{\"value\":\"second\"}\n"
        );
    }
}
