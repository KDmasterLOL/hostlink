//! Filesystem-specific digesting and bounded file reads.

use crate::{BoundedTail, read_bounded_bytes};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Identity of one byte stream observed while reading a file.
///
/// The byte count and digest describe bytes read during that operation. They are not a perpetual
/// freshness guarantee for the path, and concurrent file changes are outside this value's proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    bytes: u64,
    sha256: String,
}

impl FileDigest {
    /// Opens an existing ordinary file and hashes its exact bytes in one streaming pass.
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        crate::RegularFile::open_and_observe_digest(path)
    }

    pub(crate) fn from_reader(mut file: fs::File) -> io::Result<Self> {
        let mut digest = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("file byte count overflow"))?;
            digest.update(&buffer[..read]);
        }
        Ok(Self {
            bytes,
            sha256: format!("{:x}", digest.finalize()),
        })
    }

    /// Returns the exact number of bytes read while computing this digest.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Returns the lowercase SHA-256 digest of the exact observed byte stream.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Consumes this identity and returns its lowercase SHA-256 digest.
    pub fn into_sha256(self) -> String {
        self.sha256
    }
}

/// Observe exact file bytes once, counting bytes and hashing the same stream.
///
/// This compatibility helper follows a final symbolic link, matching `std::fs::File::open`.
/// Use [`FileDigest::from_path`] when the final path component must be an ordinary non-link file.
pub fn digest_file(path: &Path) -> io::Result<FileDigest> {
    FileDigest::from_reader(fs::File::open(path)?)
}

/// Hash exact file bytes without loading the whole file into memory.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    digest_file(path).map(FileDigest::into_sha256)
}

/// Read one complete file with an explicit byte ceiling.
///
/// The file length is checked before allocation and the stream is still read through
/// [`read_bounded_bytes`] so growth after the metadata check cannot bypass the cap.
pub fn read_file_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    if max_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file byte limit must be greater than zero",
        ));
    }
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    read_bounded_bytes(&mut file, Some(len), max_bytes)
}

/// Read at most `max_bytes` from the tail of one ordinary file.
///
/// Unlike [`crate::RetainedLog::read_tail`], this helper has no rotation/companion-file
/// semantics and is suitable for files written directly by external executables.
pub fn read_file_tail_bounded(path: &Path, max_bytes: usize) -> io::Result<BoundedTail> {
    if max_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file tail byte limit must be greater than zero",
        ));
    }
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let requested = len.min(max_bytes as u64);
    file.seek(SeekFrom::Start(len.saturating_sub(requested)))?;
    let mut bytes = Vec::with_capacity(requested as usize);
    file.take(requested).read_to_end(&mut bytes)?;
    Ok(BoundedTail {
        bytes,
        truncated: len > requested,
    })
}

/// Compact one completed file to its final `max_bytes` bytes.
///
/// Returns `true` when earlier bytes were discarded. Callers must invoke this only after the
/// external writer has completed; publication atomically replaces the file so readers never
/// observe a partially rewritten retained log.
pub fn compact_file_tail_bounded(path: &Path, max_bytes: usize) -> io::Result<bool> {
    let tail = read_file_tail_bounded(path, max_bytes)?;
    if tail.truncated {
        crate::write_file_atomically(path, &tail.bytes)?;
    }
    Ok(tail.truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn regression_inv_134_digest_file_counts_and_hashes_the_same_exact_bytes() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("payload.bin");
        let payload = b"abc\r\n\0def";
        fs::write(&path, payload).expect("fixture");

        let observed = digest_file(&path).expect("digest");

        assert_eq!(observed.bytes(), payload.len() as u64);
        assert_eq!(observed.sha256(), format!("{:x}", Sha256::digest(payload)));
        assert_eq!(
            sha256_file(&path).expect("compatibility sha256"),
            observed.sha256()
        );
    }

    #[cfg(unix)]
    #[test]
    fn free_digest_helpers_follow_final_symlinks_but_from_path_rejects_them() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("target.bin");
        let link = dir.path().join("link.bin");
        fs::write(&target, b"linked bytes").expect("target");
        symlink(&target, &link).expect("symlink");

        assert_eq!(digest_file(&link).unwrap().bytes(), 12);
        assert_eq!(
            sha256_file(&link).unwrap(),
            digest_file(&target).unwrap().sha256()
        );
        assert!(FileDigest::from_path(&link).is_err());
    }

    #[test]
    fn regression_inv_104_complete_file_read_rejects_oversize_before_loading_body() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("result.json");
        fs::write(&path, vec![b'x'; 1025]).expect("fixture");
        let error = read_file_bounded(&path, 1024).expect_err("oversize must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn regression_inv_104_single_file_tail_is_bounded_and_lossy_utf8_safe() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("external.log");
        let mut bytes = vec![b'x'; 2 * 1024 * 1024];
        bytes.extend_from_slice("🙂tail".as_bytes());
        fs::write(&path, bytes).expect("fixture");

        let tail = read_file_tail_bounded(&path, 9).expect("tail");
        assert!(tail.truncated);
        assert!(tail.bytes.len() <= 9);
        let text = String::from_utf8_lossy(&tail.bytes);
        assert!(text.ends_with("tail"), "{text:?}");
    }

    #[test]
    fn regression_inv_104_completed_file_compaction_keeps_only_tail_atomically() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("retained.log");
        let mut bytes = vec![b'x'; 4096];
        bytes.extend_from_slice(b"retained-tail");
        fs::write(&path, bytes).expect("fixture");

        assert!(compact_file_tail_bounded(&path, 1024).expect("compact"));
        let retained = fs::read(&path).expect("retained");
        assert_eq!(retained.len(), 1024);
        assert!(retained.ends_with(b"retained-tail"));
        assert!(!compact_file_tail_bounded(&path, 1024).expect("idempotent compact"));
    }
}
