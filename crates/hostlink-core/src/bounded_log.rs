//! Retained process-output logs backed by file-rotate.

use crate::filesystem::{
    open_private_append, open_private_read_existing, open_private_read_write_existing,
    validate_private_parent,
};
use crate::{move_file_atomically, write_new_private_bytes};
use file_rotate::{
    ContentLimit, FileRotate,
    compression::Compression,
    suffix::{AppendCount, Representation, SuffixScheme},
};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Tail bytes plus caller-side and durable-storage truncation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedLogTail {
    /// Returned bytes in chronological order.
    pub bytes: Vec<u8>,
    /// The returned tail omits historical bytes.
    pub truncated: bool,
    /// Older bytes were already discarded by durable storage rotation.
    pub storage_truncated: bool,
}

/// Owns the path and history semantics for one private retained process log.
#[derive(Debug, Clone)]
pub struct RetainedLog {
    path: PathBuf,
}

impl RetainedLog {
    /// Create a retained-log handle for a path ending in `.log`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when the path does not end in `.log`.
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        companion_paths(&path)?;
        Ok(Self { path })
    }

    /// Return the active log path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open a private writer retaining at most the active and one rotated segment.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment limit is invalid, the private path cannot be opened,
    /// or a legacy retained-log layout is ambiguous or cannot be migrated.
    pub fn writer(&self, segment_bytes: u64) -> io::Result<RetainedLogWriter> {
        RetainedLogWriter::open(&self.path, segment_bytes)
    }

    /// Read at most `tail_bytes` from retained chronological history.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a segment cannot be read or old and native rotated layouts are
    /// both present.
    pub fn read_tail(&self, tail_bytes: u64) -> io::Result<RetainedLogTail> {
        read_retained_log_tail(&self.path, tail_bytes)
    }

    /// Return whether durable rotation has already discarded historical bytes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the history marker cannot be inspected.
    pub fn storage_truncated(&self) -> io::Result<bool> {
        retained_log_storage_truncated(&self.path)
    }

    /// Remove all active, rotated, legacy, and marker files owned by this log family.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for an invalid path, failed segment scan, or failed removal.
    pub fn reset(&self) -> io::Result<()> {
        reset_retained_log(&self.path)
    }
}

/// Private writer for durable raw process output owned by a [`RetainedLog`].
pub struct RetainedLogWriter {
    inner: FileRotate<AppendCount>,
}

impl RetainedLogWriter {
    /// Flush buffered bytes and synchronize the active segment to stable storage.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when flushing or synchronizing the active segment fails.
    pub fn sync_all(&mut self) -> io::Result<()> {
        self.inner.sync_all()
    }

    fn open(path: &Path, segment_bytes: u64) -> io::Result<Self> {
        companion_paths(path)?;
        if segment_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retained log segment size must be greater than zero",
            ));
        }
        let segment_limit = usize::try_from(segment_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "retained log segment size exceeds this platform's addressable size",
            )
        })?;

        // Legacy migration uses path-based rename/marker helpers. Prove the immediate ownership
        // directory before any such operation so a pre-existing parent symlink/reparse point
        // cannot redirect migration outside the private boundary.
        validate_private_parent(path)?;
        migrate_legacy_layout(path, segment_bytes, segment_limit)?;

        let mut inner = FileRotate::try_new_with_file_opener(
            path,
            AppendCount::new(1),
            ContentLimit::Bytes(segment_limit),
            Compression::None,
            open_private_append,
        )?;
        inner.set_eviction_hook(record_history_loss);
        Ok(Self { inner })
    }
}

impl Write for RetainedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Return whether durable rotation has already discarded historical bytes.
fn retained_log_storage_truncated(path: &Path) -> io::Result<bool> {
    let (_, marker) = companion_paths(path)?;
    if !validate_parent_if_present(path)? {
        return Ok(false);
    }
    Ok(open_retained_segment(&marker)?.is_some())
}

/// Remove all files owned by one retained-log family.
///
/// Missing files are accepted.
///
/// # Errors
///
/// Returns an I/O error for an invalid path, failed segment scan, or failed removal.
fn reset_retained_log(path: &Path) -> io::Result<()> {
    if !validate_parent_if_present(path)? {
        return Ok(());
    }
    let (legacy, marker) = companion_paths(path)?;
    for candidate in native_segments(path)?
        .into_iter()
        .chain([legacy, marker, path.to_path_buf()])
    {
        remove_file_if_present(&candidate)?;
    }
    Ok(())
}

/// Read at most `tail_bytes` from retained process-log history.
fn read_retained_log_tail(path: &Path, tail_bytes: u64) -> io::Result<RetainedLogTail> {
    if !validate_parent_if_present(path)? {
        return Ok(RetainedLogTail {
            bytes: Vec::new(),
            truncated: false,
            storage_truncated: false,
        });
    }
    let (legacy, marker) = companion_paths(path)?;
    let storage_truncated = open_retained_segment(&marker)?.is_some();
    let mut paths = native_segments(path)?;
    if legacy.try_exists()? {
        if !paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained log contains both legacy and native rotated history",
            ));
        }
        paths.push(legacy);
    }
    paths.push(path.to_path_buf());

    let segments = paths
        .iter()
        .map(|path| open_retained_segment(path))
        .collect::<io::Result<Vec<_>>>()?;
    let lengths = segments
        .iter()
        .map(|file| {
            file.as_ref()
                .map(|file| file.metadata().map(|metadata| metadata.len()))
                .transpose()
                .map(|len| len.unwrap_or(0))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let total_len = lengths.iter().sum();
    if tail_bytes == 0 || total_len == 0 {
        return Ok(RetainedLogTail {
            bytes: Vec::new(),
            truncated: total_len > 0 || storage_truncated,
            storage_truncated,
        });
    }

    let requested = usize::try_from(tail_bytes.min(total_len)).map_err(io::Error::other)?;
    let mut bytes = vec![0; requested];
    let mut end = requested;
    for (mut file, len) in segments.into_iter().zip(lengths).rev() {
        let take = end.min(usize::try_from(len).unwrap_or(usize::MAX));
        if take == 0 {
            continue;
        }
        let start = end - take;
        let file = file
            .as_mut()
            .expect("non-empty retained segment has an open file");
        file.seek(SeekFrom::Start(len - take as u64))?;
        file.read_exact(&mut bytes[start..end])?;
        end = start;
        if end == 0 {
            break;
        }
    }
    Ok(RetainedLogTail {
        bytes,
        truncated: total_len > requested as u64 || storage_truncated,
        storage_truncated,
    })
}

fn migrate_legacy_layout(path: &Path, segment_bytes: u64, segment_limit: usize) -> io::Result<()> {
    let (legacy, _) = companion_paths(path)?;
    let native = 1_usize.to_path(path);
    if legacy.try_exists()? {
        if !native_segments(path)?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained log contains both legacy and native rotated history",
            ));
        }
        move_file_atomically(&legacy, &native)?;
    }

    if path.try_exists()? {
        let mut file = open_private_read_write_existing(path)?;
        let len = file.metadata()?.len();
        if len <= segment_bytes {
            return Ok(());
        }
        let requested = len.min(segment_limit as u64);
        file.seek(SeekFrom::Start(len.saturating_sub(requested)))?;
        let mut keep = Vec::with_capacity(requested as usize);
        Read::by_ref(&mut file)
            .take(requested)
            .read_to_end(&mut keep)?;
        record_history_loss(path, path)?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&keep)?;
        file.sync_all()?;
    }
    Ok(())
}

fn record_history_loss(base_path: &Path, _evicted_path: &Path) -> io::Result<()> {
    let marker = companion_paths(base_path)?.1;
    if !marker.try_exists()? {
        write_new_private_bytes(&marker, b"truncated\n")?;
    }
    Ok(())
}

fn native_segments(path: &Path) -> io::Result<Vec<PathBuf>> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no parent"))?;
    if !parent.try_exists()? {
        return Ok(Vec::new());
    }
    AppendCount::new(usize::MAX)
        .try_scan_suffixes(path)?
        .into_iter()
        .rev()
        .map(|suffix| {
            (!suffix.compressed)
                .then(|| suffix.to_path(path))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "compressed bounded process-log history is unsupported",
                    )
                })
        })
        .collect()
}

fn companion_paths(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    if path.extension() != Some(OsStr::new("log")) || path.parent().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "retained log path must end in .log and have a parent",
        ));
    }
    Ok((
        path.with_extension("prev.log"),
        path.with_extension("truncated"),
    ))
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_parent_if_present(path: &Path) -> io::Result<bool> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no parent"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    if !parent.try_exists()? {
        return Ok(false);
    }
    validate_private_parent(path)?;
    Ok(true)
}

fn open_retained_segment(path: &Path) -> io::Result<Option<fs::File>> {
    match open_private_read_existing(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::restrict_private_directory(dir.path()).expect("private tempdir");
        dir
    }

    #[test]
    fn keeps_latest_two_segments_and_marks_history_loss() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        let mut writer = RetainedLog::new(&path)
            .expect("retained log")
            .writer(8)
            .expect("retained log");

        writer.write_all(b"AAAAAAAA").expect("first segment");
        writer.write_all(b"BBBBBBBB").expect("second segment");
        writer.write_all(b"TAIL").expect("third segment");
        writer.sync_all().expect("sync");
        drop(writer);

        assert_eq!(
            fs::read(dir.path().join("stdout.log.1")).expect("previous"),
            b"BBBBBBBB"
        );
        assert_eq!(fs::read(&path).expect("active"), b"TAIL");
        assert!(dir.path().join("stdout.truncated").is_file());

        let tail = RetainedLog::new(&path)
            .expect("retained log")
            .read_tail(10)
            .expect("tail");
        assert_eq!(tail.bytes, b"BBBBBBTAIL");
        assert!(tail.truncated);
        assert!(tail.storage_truncated);
    }

    #[test]
    fn migrates_legacy_previous_segment_on_writer_open() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"NEW").expect("active");
        fs::write(dir.path().join("stdout.prev.log"), b"OLD").expect("legacy previous");

        let mut writer = RetainedLog::new(&path)
            .expect("retained log")
            .writer(8)
            .expect("retained log");
        writer.sync_all().expect("sync");
        drop(writer);

        assert!(!dir.path().join("stdout.prev.log").exists());
        assert_eq!(
            fs::read(dir.path().join("stdout.log.1")).expect("native previous"),
            b"OLD"
        );
        let tail = RetainedLog::new(&path)
            .expect("retained log")
            .read_tail(8)
            .expect("tail");
        assert_eq!(tail.bytes, b"OLDNEW");
        assert!(!tail.storage_truncated);
    }

    #[test]
    fn reads_legacy_previous_segment_without_reopening_writer() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"NEW").expect("active");
        fs::write(dir.path().join("stdout.prev.log"), b"OLD").expect("legacy previous");

        let tail = RetainedLog::new(&path)
            .expect("retained log")
            .read_tail(5)
            .expect("tail");

        assert_eq!(tail.bytes, b"LDNEW");
        assert!(tail.truncated);
        assert!(!tail.storage_truncated);
        assert!(dir.path().join("stdout.prev.log").is_file());
    }

    #[test]
    fn rejects_ambiguous_mixed_legacy_and_native_history() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"ACTIVE").expect("active");
        fs::write(dir.path().join("stdout.prev.log"), b"LEGACY").expect("legacy previous");
        fs::write(dir.path().join("stdout.log.1"), b"NATIVE").expect("native previous");

        let error = RetainedLog::new(&path)
            .expect("retained log")
            .writer(8)
            .err()
            .expect("mixed layout must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = RetainedLog::new(&path)
            .expect("retained log")
            .read_tail(8)
            .expect_err("mixed tail must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn compacts_oversized_legacy_active_segment() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"0123456789").expect("legacy log");

        let mut writer = RetainedLog::new(&path)
            .expect("retained log")
            .writer(4)
            .expect("retained log");
        writer.sync_all().expect("sync");
        drop(writer);

        assert_eq!(fs::read(&path).expect("active"), b"6789");
        assert!(dir.path().join("stdout.truncated").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn oversized_symlink_active_log_is_rejected_without_mutating_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = private_tempdir();
        let outside = dir.path().join("outside.txt");
        let path = dir.path().join("stdout.log");
        let original = b"0123456789";
        fs::write(&outside, original).expect("outside file");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).expect("outside mode");
        symlink(&outside, &path).expect("active log symlink");

        assert!(
            RetainedLog::new(&path)
                .expect("retained log")
                .writer(4)
                .is_err()
        );
        assert_eq!(fs::read(&outside).expect("outside bytes"), original);
        assert_eq!(
            fs::metadata(&outside)
                .expect("outside metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(!dir.path().join("stdout.truncated").exists());
    }

    #[cfg(unix)]
    #[test]
    fn tail_rejects_symlinked_active_log() {
        use std::os::unix::fs::symlink;

        let dir = private_tempdir();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"external secret").expect("outside file");
        let path = dir.path().join("stdout.log");
        symlink(&outside, &path).expect("active log symlink");

        assert!(
            RetainedLog::new(path)
                .expect("retained log")
                .read_tail(64)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_is_rejected_before_legacy_migration() {
        use std::os::unix::fs::symlink;

        let dir = private_tempdir();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        crate::restrict_private_directory(&outside).expect("private outside directory");
        let legacy = outside.join("stdout.prev.log");
        fs::write(&legacy, b"legacy external bytes").expect("legacy external file");
        let alias = dir.path().join("alias");
        symlink(&outside, &alias).expect("parent symlink");

        assert!(
            RetainedLog::new(alias.join("stdout.log"))
                .expect("retained log")
                .writer(4)
                .is_err()
        );
        assert_eq!(
            fs::read(&legacy).expect("legacy external bytes"),
            b"legacy external bytes"
        );
        assert!(!outside.join("stdout.log.1").exists());
        assert!(!outside.join("stdout.truncated").exists());
    }

    #[cfg(unix)]
    #[test]
    fn reset_rejects_symlinked_parent_without_removing_target_files() {
        use std::os::unix::fs::symlink;

        let dir = private_tempdir();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        crate::restrict_private_directory(&outside).expect("private outside directory");
        fs::write(outside.join("stdout.log"), b"active").expect("active log");
        fs::write(outside.join("stdout.log.1"), b"previous").expect("rotated log");
        fs::write(outside.join("stdout.truncated"), b"truncated\n").expect("history marker");
        let alias = dir.path().join("alias");
        symlink(&outside, &alias).expect("parent symlink");

        assert!(
            RetainedLog::new(alias.join("stdout.log"))
                .expect("retained log")
                .reset()
                .is_err()
        );
        assert_eq!(
            fs::read(outside.join("stdout.log")).expect("active log"),
            b"active"
        );
        assert_eq!(
            fs::read(outside.join("stdout.log.1")).expect("rotated log"),
            b"previous"
        );
        assert!(outside.join("stdout.truncated").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn tail_rejects_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let dir = private_tempdir();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        crate::restrict_private_directory(&outside).expect("private outside directory");
        fs::write(outside.join("stdout.log"), b"external secret").expect("external log");
        let alias = dir.path().join("alias");
        symlink(&outside, &alias).expect("parent symlink");

        assert!(
            RetainedLog::new(alias.join("stdout.log"))
                .expect("retained log")
                .read_tail(64)
                .is_err()
        );
    }

    #[test]
    fn zero_tail_is_empty_and_reports_omitted_history() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"bytes").expect("log");

        let tail = RetainedLog::new(&path)
            .expect("retained log")
            .read_tail(0)
            .expect("tail");

        assert!(tail.bytes.is_empty());
        assert!(tail.truncated);
        assert!(!tail.storage_truncated);
    }

    #[test]
    fn missing_log_tail_is_empty() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");

        assert_eq!(
            RetainedLog::new(&path)
                .expect("retained log")
                .read_tail(128)
                .expect("tail"),
            RetainedLogTail {
                bytes: Vec::new(),
                truncated: false,
                storage_truncated: false,
            }
        );
    }

    #[test]
    fn retained_log_rejects_paths_without_log_extension() {
        assert!(RetainedLog::new("stdout.txt").is_err());
        assert!(RetainedLog::new(PathBuf::from("stdout.log")).is_ok());
        assert!(RetainedLog::new(PathBuf::from(".").join("stdout.log")).is_ok());
    }

    #[test]
    fn reset_removes_native_legacy_and_marker_state() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        fs::write(&path, b"active").expect("active");
        fs::write(dir.path().join("stdout.log.1"), b"native").expect("native");
        fs::write(dir.path().join("stdout.log.2"), b"older native").expect("older native");
        fs::write(dir.path().join("stdout.prev.log"), b"legacy").expect("legacy");
        fs::write(dir.path().join("stdout.truncated"), b"truncated\n").expect("marker");
        fs::write(dir.path().join("unrelated.txt"), b"keep").expect("unrelated");

        RetainedLog::new(&path)
            .expect("retained log")
            .reset()
            .expect("reset");

        assert!(!path.exists());
        assert!(!dir.path().join("stdout.log.1").exists());
        assert!(!dir.path().join("stdout.log.2").exists());
        assert!(!dir.path().join("stdout.prev.log").exists());
        assert!(!dir.path().join("stdout.truncated").exists());
        assert_eq!(
            fs::read(dir.path().join("unrelated.txt")).expect("unrelated"),
            b"keep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rotated_and_active_segments_remain_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        let mut writer = RetainedLog::new(&path)
            .expect("retained log")
            .writer(4)
            .expect("retained log");
        writer.write_all(b"ABCDEFGHI").expect("write");
        writer.sync_all().expect("sync");
        drop(writer);

        for path in [
            &path,
            &dir.path().join("stdout.log.1"),
            &dir.path().join("stdout.truncated"),
        ] {
            let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{path:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn rotated_active_and_history_marker_have_private_windows_acl() {
        let dir = private_tempdir();
        let path = dir.path().join("stdout.log");
        let mut writer = RetainedLog::new(&path)
            .expect("retained log")
            .writer(4)
            .expect("retained log");
        writer.write_all(b"ABCDEFGHI").expect("write");
        writer.sync_all().expect("sync");
        drop(writer);

        for path in [
            &path,
            &dir.path().join("stdout.log.1"),
            &dir.path().join("stdout.truncated"),
        ] {
            crate::validate_private_file(path).expect("private retained-log file");
        }
    }
}
