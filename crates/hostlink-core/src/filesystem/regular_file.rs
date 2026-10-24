//! Handle-validated identity for an existing ordinary file.

use super::io_util::FileDigest;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// An observed path to an existing regular file.
///
/// Opening rejects a final symbolic link on Unix and a final reparse point on Windows. The
/// identity is checked again whenever bytes are observed; replacing or removing the file after
/// construction therefore fails instead of silently observing a different file. The value does
/// not keep a handle open or promise that the path remains available between operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularFile {
    path: PathBuf,
    identity: FileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume: u32,
    #[cfg(windows)]
    index: u64,
}

impl RegularFile {
    /// Opens and validates an existing regular file without following a final link/reparse point.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = open_file(&path)?;
        let identity = file_identity(&file)?;
        Ok(Self { path, identity })
    }

    pub(crate) fn open_and_observe_digest(path: impl AsRef<Path>) -> io::Result<FileDigest> {
        let file = open_file(path.as_ref())?;
        file_identity(&file)?;
        FileDigest::from_reader(file)
    }

    /// Returns the original native path without converting it to UTF-8.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reopens this path, verifies the same regular-file identity, and hashes that handle's bytes.
    pub fn observe_digest(&self) -> io::Result<FileDigest> {
        let file = open_file(&self.path)?;
        let actual = file_identity(&file)?;
        if actual != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("regular file identity changed: {}", self.path.display()),
            ));
        }
        FileDigest::from_reader(file)
    }

    /// Reopens the same ordinary non-link file and reads at most the supplied byte bound.
    ///
    /// Revalidates the captured file identity on the opened handle, so a substituted
    /// symlink/reparse point cannot be read between metadata inspection and parsing.
    pub fn read_bounded(&self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut file = open_file(&self.path)?;
        if file_identity(&file)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "regular file identity changed before reading",
            ));
        }
        let length = file.metadata()?.len();
        crate::read_bounded_bytes(&mut file, Some(length), max_bytes)
    }
}

impl AsRef<Path> for RegularFile {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

fn open_file(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK prevents a FIFO substituted at the path from hanging before fstat rejects it.
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        // Windows requires BACKUP_SEMANTICS to open directories. Opening the handle lets
        // `file_identity` reject them as InvalidInput instead of leaking CreateFile's
        // PermissionDenied result; OPEN_REPARSE_POINT still prevents following the leaf.
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }

    #[cfg(unix)]
    {
        options.open(path).map_err(|error| {
            if error.raw_os_error() == Some(nix::libc::ELOOP) {
                io::Error::new(io::ErrorKind::InvalidInput, error)
            } else {
                error
            }
        })
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

fn file_identity(file: &fs::File) -> io::Result<FileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || handle_is_reparse(file, &metadata)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path does not identify a regular non-link file",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    {
        let (volume, index, _) = windows_file_identity(file)?;
        Ok(FileIdentity { volume, index })
    }
}

#[cfg(unix)]
fn handle_is_reparse(_: &fs::File, _: &fs::Metadata) -> io::Result<bool> {
    Ok(false)
}

#[cfg(windows)]
fn handle_is_reparse(file: &fs::File, _: &fs::Metadata) -> io::Result<bool> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    Ok(windows_file_identity(file)?.2 & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(windows)]
fn windows_file_identity(file: &fs::File) -> io::Result<(u32, u64, u32)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the borrowed std file handle stays open for the duration of this call.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        info.dwFileAttributes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn opens_and_hashes_exact_binary_bytes_including_bom() {
        use sha2::{Digest as _, Sha256};

        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("payload.bin");
        let payload = b"\xef\xbb\xbf\x00binary\xff\r\n";
        fs::write(&path, payload).expect("fixture");

        let file = RegularFile::open(&path).expect("regular file");
        assert_eq!(
            file.read_bounded(payload.len())
                .expect("bounded regular read"),
            payload
        );
        assert!(file.read_bounded(payload.len() - 1).is_err());
        let digest = file.observe_digest().expect("digest");
        assert_eq!(digest.bytes(), payload.len() as u64);
        assert_eq!(digest.sha256(), format!("{:x}", Sha256::digest(payload)));
        assert_eq!(file.path(), path);
    }

    #[test]
    fn rejects_missing_paths_and_directories() {
        let directory = tempdir().expect("tempdir");
        assert_eq!(
            RegularFile::open(directory.path().join("missing"))
                .expect_err("missing")
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            RegularFile::open(directory.path())
                .expect_err("directory")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_preserves_non_utf8_names() {
        use std::os::unix::{ffi::OsStringExt, fs::symlink};

        let directory = tempdir().expect("tempdir");
        let mut name = b"ordinary-".to_vec();
        name.push(0xff);
        let path = directory.path().join(std::ffi::OsString::from_vec(name));
        fs::write(&path, b"data").expect("fixture");
        assert_eq!(RegularFile::open(&path).unwrap().path(), path);

        let link = directory.path().join("link");
        symlink(&path, &link).expect("symlink");
        assert!(RegularFile::open(link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_file_symlink_reparse_points_when_creation_is_available() {
        use std::os::windows::fs::symlink_file;

        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("target.bin");
        let link = directory.path().join("link.bin");
        fs::write(&target, b"target").expect("fixture");
        if let Err(error) = symlink_file(&target, &link) {
            // Windows may disable symlink creation for an unprivileged test process.
            if matches!(error.raw_os_error(), Some(5 | 50 | 1314)) {
                return;
            }
            panic!("create file symlink: {error}");
        }

        assert_eq!(
            RegularFile::open(link)
                .expect_err("final reparse point must be rejected")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_special_files_without_waiting_for_a_peer() {
        let directory = tempdir().expect("tempdir");
        let fifo = directory.path().join("input.fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("fifo fixture");

        assert_eq!(
            RegularFile::open(fifo)
                .expect_err("FIFO is not a regular file")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rejects_replaced_or_removed_file_on_observation() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("payload");
        fs::write(&path, b"original").expect("fixture");
        let file = RegularFile::open(&path).expect("regular file");

        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"replacement").expect("replacement");
        fs::rename(&replacement, &path).expect("replace path");
        assert_eq!(
            file.observe_digest()
                .expect_err("replacement rejected")
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            file.read_bounded(128)
                .expect_err("replacement cannot be read")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn observes_updated_bytes_when_the_same_file_is_written_in_place() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("payload");
        fs::write(&path, b"before").expect("fixture");
        let file = RegularFile::open(&path).expect("regular file");

        fs::write(&path, b"after!").expect("in-place update");

        let digest = file.observe_digest().expect("same identity remains valid");
        assert_eq!(digest.bytes(), 6);
        assert_eq!(
            digest.sha256(),
            FileDigest::from_path(&path).unwrap().sha256()
        );
    }
}
