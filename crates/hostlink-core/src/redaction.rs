//! Chunk-safe streaming byte redaction for persisted or forwarded output.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::io::{self, Write};

const REDACTED: &[u8] = b"[REDACTED]";

/// Writer adapter that redacts exact byte patterns even when a pattern crosses input chunks.
pub struct RedactingWriter<W> {
    inner: W,
    pending: Vec<u8>,
    matcher: Option<AhoCorasick>,
    max_pattern_len: usize,
}

impl<W: Write> RedactingWriter<W> {
    /// Wrap a writer with exact-pattern redaction.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when the pattern set exceeds the matcher limits.
    pub fn new(inner: W, mut patterns: Vec<Vec<u8>>) -> io::Result<Self> {
        normalize_patterns(&mut patterns);
        let max_pattern_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let matcher = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&patterns)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            )
        };

        Ok(Self {
            inner,
            pending: Vec::new(),
            matcher,
            max_pattern_len,
        })
    }

    /// Consume another chunk while retaining enough suffix bytes to detect split patterns.
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.pending.extend_from_slice(bytes);
        self.flush_available(false)
    }

    /// Flush the final pending bytes and return the wrapped writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush_available(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn flush_available(&mut self, final_flush: bool) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let Some(matcher) = self.matcher.as_ref() else {
            self.inner.write_all(&self.pending)?;
            self.pending.clear();
            return Ok(());
        };

        let keep = if final_flush {
            0
        } else {
            self.max_pattern_len.saturating_sub(1)
        };
        let emit_limit = self.pending.len().saturating_sub(keep);
        if emit_limit == 0 {
            return Ok(());
        }

        let mut emitted = 0usize;
        let mut drain_until = emit_limit;
        for matched in matcher.find_iter(&self.pending) {
            if matched.start() >= emit_limit {
                break;
            }
            if emitted < matched.start() {
                self.inner
                    .write_all(&self.pending[emitted..matched.start()])?;
            }
            self.inner.write_all(REDACTED)?;
            emitted = matched.end();
            drain_until = drain_until.max(matched.end());
        }
        if emitted < emit_limit {
            self.inner.write_all(&self.pending[emitted..emit_limit])?;
        }

        self.pending.drain(..drain_until);
        Ok(())
    }
}

fn normalize_patterns(patterns: &mut Vec<Vec<u8>>) {
    patterns.retain(|pattern| !pattern.is_empty());
    patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    patterns.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(chunks: &[&[u8]], patterns: Vec<Vec<u8>>) -> Vec<u8> {
        let mut writer = RedactingWriter::new(Vec::new(), patterns).expect("matcher");
        for chunk in chunks {
            writer.push(chunk).expect("push");
        }
        writer.finish().expect("finish")
    }

    #[test]
    fn streaming_redaction_handles_split_pattern() {
        let output = redact(
            &[b"prefix SECRET", b"-VALUE suffix"],
            vec![b"SECRET-VALUE".to_vec()],
        );
        assert_eq!(output, b"prefix [REDACTED] suffix");
    }

    #[test]
    fn longer_overlapping_patterns_win() {
        let output = redact(
            &[b"token=secret-long"],
            vec![b"secret".to_vec(), b"secret-long".to_vec()],
        );
        assert_eq!(output, b"token=[REDACTED]");
    }

    #[test]
    fn duplicates_and_empty_patterns_do_not_change_output() {
        let output = redact(
            &[b"secret other secret"],
            vec![
                Vec::new(),
                b"secret".to_vec(),
                b"other".to_vec(),
                b"secret".to_vec(),
            ],
        );
        assert_eq!(output, b"[REDACTED] [REDACTED] [REDACTED]");
    }

    #[test]
    fn binary_non_utf8_secret_is_redacted() {
        let secret = vec![0x00, 0xFF, 0x10, 0x80];
        let input = [b"prefix".as_slice(), secret.as_slice(), b"suffix"].concat();
        let output = redact(&[&input], vec![secret]);
        assert_eq!(output, b"prefix[REDACTED]suffix");
    }

    #[test]
    fn secret_is_redacted_at_every_chunk_boundary() {
        let secret = b"SECRET-VALUE";
        let input = [b"prefix ".as_slice(), secret.as_slice(), b" suffix"].concat();
        let expected = b"prefix [REDACTED] suffix";

        for split in 0..=input.len() {
            let output = redact(
                &[&input[..split], &input[split..]],
                vec![b"SECRET".to_vec(), secret.to_vec()],
            );
            assert_eq!(output, expected, "split at {split}");
        }
    }

    #[test]
    fn multiple_matches_preserve_unmatched_binary_bytes() {
        let input = b"\xF0alpha\x00beta\xFFalpha\xFE";
        let output = redact(&[input], vec![b"alpha".to_vec(), b"beta".to_vec()]);
        assert_eq!(output, b"\xF0[REDACTED]\x00[REDACTED]\xFF[REDACTED]\xFE");
    }
}
