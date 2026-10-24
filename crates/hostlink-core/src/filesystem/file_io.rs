//! Runtime-neutral private file and directory I/O helpers.

use super::private_file::{restrict_private_directory, restrict_private_file};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path};

/// Ensure a directory exists and restrict it to the current user/process owner.
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    restrict_private_directory(path).map_err(io::Error::other)
}

/// Create one new directory and restrict it to the current user/process owner.
///
/// The parent must already exist and the destination must not exist.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    if let Err(error) = restrict_private_directory(path) {
        if let Err(cleanup) = fs::remove_dir(path) {
            return Err(io::Error::other(format!(
                "failed to enforce private directory permissions for {}: {error}; failed to remove partially created directory: {cleanup}",
                path.display()
            )));
        }
        return Err(io::Error::other(error));
    }
    Ok(())
}

/// Creates one new private file and returns its open handle.
///
/// The destination must not already exist. If private permission/ACL enforcement fails after the
/// operating system creates the directory entry, the entry is removed before the error is
/// returned so callers never inherit a partially published non-private file.
///
/// # Errors
///
/// Returns an I/O error when creation, permission/ACL enforcement, or fail-clean removal fails.
pub fn create_new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;
    if let Err(error) = restrict_private_file(path) {
        drop(file);
        if let Err(cleanup) = fs::remove_file(path) {
            return Err(io::Error::other(format!(
                "failed to enforce private permissions for {}: {error}; failed to remove partially created file: {cleanup}",
                path.display()
            )));
        }
        return Err(io::Error::other(error));
    }
    Ok(file)
}

/// Create a new private file, write all bytes, and durably flush its contents.
///
/// The destination must not already exist.
pub fn write_new_private_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_new_private_file(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        if let Err(cleanup) = fs::remove_file(path) {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "failed to write private file {}: {error}; failed to remove partial file: {cleanup}",
                    path.display()
                ),
            ));
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn open_private_append(path: &Path) -> io::Result<File> {
    let (parent, file_name) = open_private_parent(path)?;
    super::private_file::validate_private_directory_handle(&parent).map_err(io::Error::other)?;

    let (file, created) = match parent.open_with(&file_name, &private_append_options(true)) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
            parent.open_with(&file_name, &private_append_options(false))?,
            false,
        ),
        Err(error) => return Err(error),
    };

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(primary) => {
            drop(file);
            return Err(cleanup_created_private_entry(
                &parent, &file_name, created, primary,
            ));
        }
    };
    if !metadata.is_file() || cap_metadata_is_symlink_or_reparse(&metadata) {
        let primary = io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private append target must be a regular file: {}",
                path.display()
            ),
        );
        drop(file);
        return Err(cleanup_created_private_entry(
            &parent, &file_name, created, primary,
        ));
    }

    let mut file = file.into_std();
    if let Err(primary) = super::private_file::restrict_private_file_handle(&mut file) {
        drop(file);
        return Err(cleanup_created_private_entry(
            &parent,
            &file_name,
            created,
            io::Error::other(primary),
        ));
    }
    Ok(file)
}

pub(crate) fn validate_private_parent(path: &Path) -> io::Result<()> {
    let (parent, _) = open_private_parent(path)?;
    super::private_file::validate_private_directory_handle(&parent).map_err(io::Error::other)
}

pub(crate) fn open_private_read_write_existing(path: &Path) -> io::Result<File> {
    let (parent, file_name) = open_private_parent(path)?;
    super::private_file::validate_private_directory_handle(&parent).map_err(io::Error::other)?;

    let mut options = CapOpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        // A FIFO must fail promptly instead of blocking while the type check waits for a peer.
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .access_mode(
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE
                    | WRITE_DAC,
            );
    }

    let file = parent.open_with(&file_name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || cap_metadata_is_symlink_or_reparse(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private file target must be a regular file: {}",
                path.display()
            ),
        ));
    }
    let mut file = file.into_std();
    super::private_file::restrict_private_file_handle(&mut file).map_err(io::Error::other)?;
    Ok(file)
}

pub(crate) fn open_private_read_existing(path: &Path) -> io::Result<File> {
    let (parent, file_name) = open_private_parent(path)?;
    super::private_file::validate_private_directory_handle(&parent).map_err(io::Error::other)?;

    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE);
    }

    let file = parent.open_with(&file_name, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || cap_metadata_is_symlink_or_reparse(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private read target must be a regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(file.into_std())
}

fn cleanup_created_private_entry(
    parent: &Dir,
    file_name: &std::ffi::OsStr,
    created: bool,
    primary: io::Error,
) -> io::Error {
    if !created {
        return primary;
    }
    match parent.remove_file(file_name) {
        Ok(()) => primary,
        Err(cleanup) => io::Error::new(
            primary.kind(),
            format!("{primary}; cleanup of newly created private file failed: {cleanup}"),
        ),
    }
}

fn private_append_options(create_new: bool) -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options.append(true).follow(FollowSymlinks::No);
    if create_new {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        // O_NONBLOCK makes special files such as FIFOs fail before they can stall a log writer.
        // Final-component link following is independently disabled through FollowSymlinks::No.
        options.mode(0o600).custom_flags(nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        // Keep the rights required to validate the opened object and apply its private DACL.
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .access_mode(
                FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | WRITE_DAC,
            );
    }
    options
}

/// Opens the immediate parent directory as the private ownership boundary.
///
/// Path aliases above this boundary are intentionally allowed. The ownership directory itself is
/// opened without following a final symlink/reparse point and must already satisfy the toolkit
/// private-directory contract before a file can be created below it.
fn open_private_parent(path: &Path) -> io::Result<(Dir, OsString)> {
    let file_name = match path.components().next_back() {
        Some(Component::Normal(name)) => name.to_os_string(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "private append path must end in a file name: {}",
                    path.display()
                ),
            ));
        }
    };
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private append path has no parent: {}", path.display()),
        )
    })?;
    if parent
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private append path must not contain parent traversal: {}",
                path.display()
            ),
        ));
    }

    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok((Dir::open_ambient_dir(".", ambient_authority())?, file_name));
    }

    let Some(parent_name) = parent.file_name() else {
        // Filesystem roots cannot themselves be symlinks/reparse directory entries.
        return Ok((
            Dir::open_ambient_dir(parent, ambient_authority())?,
            file_name,
        ));
    };
    let grandparent = parent
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let grandparent = Dir::open_ambient_dir(grandparent, ambient_authority())?;
    let parent = grandparent.open_dir_nofollow(parent_name)?;
    Ok((parent, file_name))
}

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_APPEND_DATA: u32 = 0x0000_0004;
#[cfg(windows)]
const FILE_READ_DATA: u32 = 0x0000_0001;
#[cfg(windows)]
const FILE_WRITE_DATA: u32 = 0x0000_0002;
#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
#[cfg(windows)]
const READ_CONTROL: u32 = 0x0002_0000;
#[cfg(windows)]
const SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(windows)]
const WRITE_DAC: u32 = 0x0004_0000;

fn cap_metadata_is_symlink_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::OsMetadataExt as _;
        has_reparse_attribute(metadata.file_attributes())
    }
    #[cfg(not(windows))]
    false
}

#[cfg(any(windows, test))]
fn has_reparse_attribute(attributes: u32) -> bool {
    attributes & 0x0400 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_file_handle_is_create_new_and_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("events.jsonl");

        let mut file = create_new_private_file(&path).expect("create private handle");
        file.write_all(b"event\n").expect("write through handle");
        file.sync_all().expect("sync handle");
        crate::validate_private_file(&path).expect("private file");
        assert_eq!(fs::read(&path).expect("read"), b"event\n");

        assert_eq!(
            create_new_private_file(&path)
                .expect_err("existing private file must not be reopened as create-new")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn private_bytes_are_create_new_and_durable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.bin");

        write_new_private_bytes(&path, b"first").expect("write private bytes");
        assert_eq!(fs::read(&path).expect("read"), b"first");
        assert_eq!(
            write_new_private_bytes(&path, b"second")
                .expect_err("existing file must be rejected")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        crate::validate_private_file(&path).expect("private file");
    }

    #[test]
    fn private_directory_is_restricted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private");

        create_private_directory(&path).expect("create private directory");
        assert!(path.is_dir());
        assert_eq!(
            create_private_directory(&path)
                .expect_err("existing directory must be rejected")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_append_rejects_symlink_without_changing_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("outside.log");
        let link = dir.path().join("append.log");
        fs::write(&target, b"external contents\n").expect("target file");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("target mode");
        symlink(&target, &link).expect("symlink");

        assert!(open_private_append(&link).is_err());
        assert_eq!(
            fs::read(&target).expect("target contents"),
            b"external contents\n"
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn private_append_creates_reopens_and_keeps_private_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::restrict_private_directory(dir.path()).expect("private tempdir");
        let path = dir.path().join("append.log");

        {
            let mut file = open_private_append(&path).expect("create append file");
            file.write_all(b"first").expect("first append");
            file.sync_all().expect("sync first append");
        }
        {
            let mut file = open_private_append(&path).expect("reopen append file");
            file.write_all(b"-second").expect("second append");
            file.sync_all().expect("sync second append");
        }

        assert_eq!(fs::read(&path).expect("contents"), b"first-second");
        crate::validate_private_file(&path).expect("private append file");
    }

    #[cfg(unix)]
    #[test]
    fn private_append_rejects_symlinked_parent_without_changing_external_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().expect("tempdir");
        let owned = dir.path().join("owned");
        let outside = dir.path().join("outside");
        fs::create_dir(&owned).expect("owned");
        fs::create_dir(&outside).expect("outside");
        let external = outside.join("append.log");
        fs::write(&external, b"external contents\n").expect("external file");
        fs::set_permissions(&external, fs::Permissions::from_mode(0o644)).expect("external mode");
        symlink(&outside, owned.join("redirect")).expect("parent symlink");

        assert!(open_private_append(&owned.join("redirect/append.log")).is_err());
        assert_eq!(
            fs::read(&external).expect("external contents"),
            b"external contents\n"
        );
        assert_eq!(
            fs::metadata(&external)
                .expect("external metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_append_rejects_fifo_without_waiting_for_a_reader() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().expect("tempdir");
        crate::restrict_private_directory(dir.path()).expect("private tempdir");
        let path = dir.path().join("append.fifo");
        mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("fifo");

        let started = Instant::now();
        assert!(open_private_append(&path).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "FIFO rejection blocked for {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_append_allows_alias_above_private_ownership_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let actual = dir.path().join("actual");
        let ownership = actual.join("owned");
        fs::create_dir_all(&ownership).expect("ownership directory");
        crate::restrict_private_directory(&ownership).expect("private ownership directory");
        let alias = dir.path().join("alias");
        symlink(&actual, &alias).expect("ancestor alias");

        let path = alias.join("owned/append.log");
        let mut file = open_private_append(&path).expect("append through ancestor alias");
        file.write_all(b"through alias").expect("append");
        file.sync_all().expect("sync");
        drop(file);

        assert_eq!(
            fs::read(ownership.join("append.log")).expect("contents"),
            b"through alias"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_append_rejects_non_private_ownership_directory_before_create() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let ownership = dir.path().join("owned");
        fs::create_dir(&ownership).expect("ownership directory");
        fs::set_permissions(&ownership, fs::Permissions::from_mode(0o755))
            .expect("permissive ownership directory");
        let path = ownership.join("append.log");

        assert!(open_private_append(&path).is_err());
        assert!(
            !path.exists(),
            "unsafe ownership boundary must fail before create"
        );
    }

    #[test]
    fn reparse_attribute_check_is_pure() {
        assert!(!has_reparse_attribute(0));
        assert!(!has_reparse_attribute(0x0010));
        assert!(has_reparse_attribute(0x0400));
        assert!(has_reparse_attribute(0x0410));
    }
}
