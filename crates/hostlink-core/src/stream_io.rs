//! Bounded operations over arbitrary `Read` streams, independent of filesystem paths.

use std::collections::VecDeque;
use std::io::{self, Read};

/// Read at most `max_bytes` from a stream without trusting an advertised length.
///
/// If `known_length` is present and already exceeds the caller-owned limit, the
/// function fails before allocating/reading the body. Otherwise it reads at most
/// `max_bytes + 1` bytes so an unknown or false length cannot bypass the cap.
pub fn read_bounded_bytes<R: Read>(
    reader: &mut R,
    known_length: Option<u64>,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    if known_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "stream body exceeds maximum of {max_bytes} bytes (advertised length {})",
                known_length.expect("checked Some")
            ),
        ));
    }

    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "byte limit is too large"))?;
    let initial_capacity = known_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(max_bytes.min(64 * 1024))
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut limited = reader.take(read_limit as u64);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stream body exceeds maximum of {max_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

/// A bounded tail read from a file or arbitrary byte stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundedTail {
    /// Returned bytes from the end of the stream.
    pub bytes: Vec<u8>,
    /// Earlier bytes existed but were intentionally not loaded.
    pub truncated: bool,
}

/// Drain one stream to EOF while retaining only its final `max_bytes` bytes.
pub fn read_stream_tail_bounded(
    reader: &mut impl Read,
    max_bytes: usize,
) -> io::Result<BoundedTail> {
    if max_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream tail byte limit must be greater than zero",
        ));
    }
    let mut tail = VecDeque::with_capacity(max_bytes);
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if read >= max_bytes {
            truncated |= read > max_bytes || !tail.is_empty();
            tail.clear();
            tail.extend(&buffer[read - max_bytes..read]);
            continue;
        }
        let overflow = tail.len().saturating_add(read).saturating_sub(max_bytes);
        if overflow > 0 {
            truncated = true;
            tail.drain(..overflow);
        }
        tail.extend(&buffer[..read]);
    }
    Ok(BoundedTail {
        bytes: tail.into_iter().collect(),
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn bounded_reader_rejects_known_oversize_before_first_read() {
        struct CountingReader {
            reads: usize,
        }

        impl Read for CountingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                Ok(0)
            }
        }

        let mut reader = CountingReader { reads: 0 };
        let error = read_bounded_bytes(&mut reader, Some(6), 5)
            .expect_err("known oversized body must fail before reading");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.reads, 0);
    }

    #[test]
    fn bounded_reader_enforces_known_and_streamed_limits() {
        let mut exact = b"12345".as_slice();
        assert_eq!(
            read_bounded_bytes(&mut exact, Some(5), 5).unwrap(),
            b"12345"
        );

        let mut advertised_too_large = b"unused".as_slice();
        let error = read_bounded_bytes(&mut advertised_too_large, Some(6), 5)
            .expect_err("known oversized body must fail before reading");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut unknown_too_large = b"123456".as_slice();
        let error = read_bounded_bytes(&mut unknown_too_large, None, 5)
            .expect_err("unknown-length body must be bounded while reading");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut one_over = b"123456".as_slice();
        assert!(read_bounded_bytes(&mut one_over, Some(5), 5).is_err());
    }

    #[test]
    fn regression_inv_104_stream_tail_drains_without_unbounded_capture() {
        let source = vec![b'z'; 3 * 1024 * 1024];
        let mut reader = source.as_slice();
        let tail = read_stream_tail_bounded(&mut reader, 4096).expect("stream tail");
        assert!(tail.truncated);
        assert_eq!(tail.bytes.len(), 4096);
        assert!(tail.bytes.iter().all(|byte| *byte == b'z'));
    }
}
