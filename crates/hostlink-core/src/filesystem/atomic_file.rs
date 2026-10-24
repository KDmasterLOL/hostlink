//! Runtime-neutral atomic single-file publication backed by `atomicwrites`.

use atomicwrites::{AllowOverwrite, AtomicFile, DisallowOverwrite, OverwriteBehavior};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

/// Write all bytes, durably flush them, and atomically replace the destination.
///
/// The shared `atomicwrites` backend synchronizes the temporary file before publication. On
/// Unix it also synchronizes the parent directory after rename; on Windows publication uses
/// `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`. Callers must not repeat those durability
/// barriers immediately after this function returns successfully.
pub fn write_file_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| file.write_all(bytes))
        .map_err(io::Error::from)
}

/// Write all bytes atomically to a destination that must not already exist.
///
/// The shared `atomicwrites` backend stages and synchronizes bytes before publishing them with
/// no-overwrite semantics, so an existing or concurrently created destination is preserved.
pub fn write_file_atomically_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    AtomicFile::new(path, DisallowOverwrite)
        .write(|file| file.write_all(bytes))
        .map_err(io::Error::from)
}

/// Write all bytes to a private same-directory staging file and atomically replace the destination.
///
/// The staging file is restricted before any caller bytes are written, then durably flushed and
/// closed before the existing atomic replacement primitive publishes it. This ensures secret or
/// otherwise private bytes are never staged in a file with ambient/default permissions. A
/// successful publication is validated as private so platform-specific rename/security semantics
/// fail visibly instead of being repaired after publication.
pub fn write_private_file_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private atomic publication destination must name a file: {}",
                path.display()
            ),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let mut staged = tempfile::Builder::new()
        .prefix(".onec-private-")
        .tempfile_in(parent)?;
    super::private_file::restrict_private_file(staged.path()).map_err(io::Error::other)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;

    let staged_path = persistent_temp_path(staged.into_temp_path())?;
    replace_file_atomically(staged_path.as_ref(), path)?;
    Ok(())
}

#[cfg(not(windows))]
fn persistent_temp_path(path: tempfile::TempPath) -> io::Result<tempfile::TempPath> {
    Ok(path)
}

#[cfg(windows)]
fn persistent_temp_path(path: tempfile::TempPath) -> io::Result<tempfile::TempPath> {
    // tempfile marks named temporary files with FILE_ATTRIBUTE_TEMPORARY on Windows. Its keep
    // operation clears that attribute before the file can become durable. Re-wrap the resulting
    // path immediately so replacement failures still have RAII cleanup.
    let kept = path.keep().map_err(|error| error.error)?;
    match tempfile::TempPath::try_from_path(kept.clone()) {
        Ok(path) => Ok(path),
        Err(error) => {
            let _ = fs::remove_file(&kept);
            Err(error)
        }
    }
}

/// Stream one file into an atomically replaced destination.
pub fn copy_file_atomically(source: &Path, destination: &Path) -> io::Result<u64> {
    let mut input = fs::File::open(source)?;
    copy_reader_atomically(&mut input, destination, AllowOverwrite)
}

/// Stream one file into a destination that must not already exist.
///
/// The source is written to a same-directory temporary file first, then published with
/// no-overwrite semantics. A concurrently created destination is therefore preserved.
pub fn copy_file_atomically_new(source: &Path, destination: &Path) -> io::Result<u64> {
    let mut input = fs::File::open(source)?;
    copy_reader_atomically(&mut input, destination, DisallowOverwrite)
}

fn copy_reader_atomically<R: Read>(
    input: &mut R,
    destination: &Path,
    overwrite: OverwriteBehavior,
) -> io::Result<u64> {
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut copied = 0_u64;
    AtomicFile::new(destination, overwrite)
        .write(|output| {
            copied = io::copy(input, output)?;
            Ok(())
        })
        .map_err(io::Error::from)?;
    Ok(copied)
}

/// Atomically replace `destination` with an already-staged same-filesystem file.
pub fn replace_file_atomically(source: &Path, destination: &Path) -> io::Result<()> {
    atomicwrites::replace_atomic(source, destination)
}

/// Atomically move `source` into a destination that must not already exist.
pub fn move_file_atomically(source: &Path, destination: &Path) -> io::Result<()> {
    atomicwrites::move_atomic(source, destination)
}

/// Atomically move a staged directory to a destination that must not already exist.
///
/// Linux and Windows use the existing `atomicwrites` no-replace rename implementations. Other
/// platforms fail closed because this operation requires an atomic directory rename that cannot
/// replace a concurrently created destination.
pub fn move_directory_atomically_new(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    {
        atomicwrites::move_atomic(source, destination)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic no-replace directory publication is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_existing_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(&path, b"old").expect("old state");
        write_file_atomically(&path, b"new").expect("atomic write");
        assert_eq!(fs::read(&path).expect("new state"), b"new");
    }

    #[test]
    fn atomic_new_write_preserves_existing_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifact.epf");
        fs::write(&path, b"original").expect("original bytes");

        let error = write_file_atomically_new(&path, b"replacement")
            .expect_err("existing destination must not be replaced");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(path).expect("original remains"), b"original");
    }

    #[test]
    fn private_atomic_write_replaces_existing_contents_and_stays_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        fs::write(&path, b"old").expect("old state");

        write_private_file_atomically(&path, b"new").expect("private atomic write");

        assert_eq!(fs::read(&path).expect("new state"), b"new");
        super::super::private_file::validate_private_file(&path)
            .expect("published file must stay private");
    }

    #[test]
    fn private_atomic_write_accepts_bare_relative_destination() {
        let cwd = std::env::current_dir().expect("current directory");
        let dir = tempfile::tempdir_in(&cwd).expect("relative tempdir");
        let relative_dir = dir.path().strip_prefix(&cwd).expect("relative directory");
        let path = relative_dir.join("state.json");

        write_private_file_atomically(&path, b"relative").expect("relative private atomic write");

        assert_eq!(fs::read(&path).expect("relative bytes"), b"relative");
        super::super::private_file::validate_private_file(&path)
            .expect("relative published file must stay private");
    }

    #[test]
    fn private_atomic_write_rejects_destination_without_file_name() {
        let error = write_private_file_atomically(Path::new(""), b"replacement")
            .expect_err("destination without a file name must be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(windows)]
    #[test]
    fn private_atomic_write_clears_windows_temporary_attribute() {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");

        write_private_file_atomically(&path, b"durable").expect("private atomic write");

        let attributes = fs::metadata(&path).expect("metadata").file_attributes();
        assert_eq!(attributes & FILE_ATTRIBUTE_TEMPORARY, 0);
        super::super::private_file::validate_private_file(&path)
            .expect("published file must stay private");
    }

    #[test]
    fn private_atomic_write_cleans_staging_when_destination_cannot_be_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let destination = dir.path().join("destination");
        fs::create_dir(&destination).expect("destination directory");

        write_private_file_atomically(&destination, b"replacement")
            .expect_err("directory destination must reject file replacement");

        assert!(destination.is_dir());
        let leftovers = fs::read_dir(dir.path())
            .expect("list tempdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(".onec-private-"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "staging files leaked: {leftovers:?}");
    }

    #[test]
    fn atomic_move_refuses_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        fs::write(&source, b"source").expect("source");
        fs::write(&destination, b"destination").expect("destination");
        assert!(move_file_atomically(&source, &destination).is_err());
        assert_eq!(fs::read(&destination).expect("destination"), b"destination");
    }

    #[test]
    fn atomic_directory_move_refuses_existing_destination_and_preserves_both_trees() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("staged");
        let destination = dir.path().join("destination");
        fs::create_dir(&source).expect("staged directory");
        fs::write(source.join("staged.txt"), b"staged").expect("staged file");
        fs::create_dir(&destination).expect("destination directory");
        fs::write(destination.join("foreign.txt"), b"foreign").expect("foreign file");

        let error = move_directory_atomically_new(&source, &destination)
            .expect_err("existing destination must not be replaced");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(destination.join("foreign.txt")).expect("foreign remains"),
            b"foreign"
        );
        assert_eq!(
            fs::read(source.join("staged.txt")).expect("staging remains"),
            b"staged"
        );
    }

    #[test]
    fn atomic_directory_move_publishes_to_missing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("staged");
        let destination = dir.path().join("destination");
        fs::create_dir(&source).expect("staged directory");
        fs::write(source.join("payload.txt"), b"payload").expect("payload");

        move_directory_atomically_new(&source, &destination).expect("publish directory");

        assert!(!source.exists());
        assert_eq!(
            fs::read(destination.join("payload.txt")).expect("published file"),
            b"payload"
        );
    }

    #[test]
    fn atomic_copy_replaces_existing_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        fs::write(&source, b"replacement").expect("source");
        fs::write(&destination, b"old").expect("old destination");
        assert_eq!(
            copy_file_atomically(&source, &destination).expect("atomic copy"),
            11
        );
        assert_eq!(fs::read(&destination).expect("destination"), b"replacement");
    }

    #[test]
    fn regression_inv_107_atomic_copy_new_refuses_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let destination = dir.path().join("destination");
        fs::write(&source, b"replacement").expect("source");
        fs::write(&destination, b"old").expect("old destination");

        let error = copy_file_atomically_new(&source, &destination)
            .expect_err("existing destination must be preserved");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).expect("destination"), b"old");
    }

    #[test]
    fn regression_inv_107_atomic_copy_preserves_destination_after_partial_reader_failure() {
        struct FailAfter {
            bytes: &'static [u8],
            offset: usize,
            fail_after: usize,
        }

        impl Read for FailAfter {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.offset >= self.fail_after {
                    return Err(io::Error::other("injected read failure"));
                }
                let available = self.fail_after.saturating_sub(self.offset);
                let remaining = &self.bytes[self.offset..];
                let count = remaining.len().min(available).min(buffer.len());
                buffer[..count].copy_from_slice(&remaining[..count]);
                self.offset += count;
                Ok(count)
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let destination = dir.path().join("destination");
        fs::write(&destination, b"old-valid-bytes").expect("old destination");
        let mut reader = FailAfter {
            bytes: b"replacement-that-must-never-be-published",
            offset: 0,
            fail_after: 12,
        };

        copy_reader_atomically(&mut reader, &destination, AllowOverwrite)
            .expect_err("injected partial copy must fail");

        assert_eq!(
            fs::read(&destination).expect("destination"),
            b"old-valid-bytes"
        );
    }
}
