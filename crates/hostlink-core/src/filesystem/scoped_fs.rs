//! Capability-rooted runtime-neutral filesystem mutation safety.

use cap_fs_ext::DirExt as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, Metadata};
use std::fs;
use std::io;
use std::path::{Component, Path};

/// Stable identity for a regular directory used as a scoped-removal boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedDirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume: u32,
    #[cfg(windows)]
    index: u64,
}

impl ScopedDirectoryIdentity {
    /// Capture the identity of an existing regular directory without following a link.
    pub fn capture(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || std_metadata_is_symlink_or_reparse(&metadata) {
            return Err(invalid_input(format!(
                "directory identity requires a regular directory, not symlink/reparse: {}",
                path.display()
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        #[cfg(windows)]
        {
            windows_directory_identity(path)
        }
    }

    fn matches_file(&self, file: &fs::File) -> io::Result<bool> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() || std_metadata_is_symlink_or_reparse(&metadata) {
            return Ok(false);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(metadata.dev() == self.device && metadata.ino() == self.inode)
        }

        #[cfg(windows)]
        {
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            let (volume, index, attributes) = windows_file_identity(file)?;
            Ok(attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && volume == self.volume
                && index == self.index)
        }
    }
}

#[cfg(windows)]
fn windows_directory_identity(path: &Path) -> io::Result<ScopedDirectoryIdentity> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let raw_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw_handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: CreateFileW returned an owned HANDLE and this File becomes its sole RAII owner.
    let handle = unsafe { fs::File::from_raw_handle(raw_handle) };
    let (volume, index, attributes) = windows_file_identity(&handle)?;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_input(format!(
            "directory identity rejects reparse point: {}",
            path.display()
        )));
    }

    Ok(ScopedDirectoryIdentity { volume, index })
}

#[cfg(windows)]
fn windows_file_identity(file: &fs::File) -> io::Result<(u32, u64, u32)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
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

/// Remove one strict descendant of an explicitly declared owned root.
///
/// The ambient absolute paths are validated only at the protocol/application boundary. After the
/// root capability is opened, target resolution and mutation are relative to that capability.
pub fn remove_path_scoped(
    root: &Path,
    path: &Path,
    recursive: bool,
    missing_ok: bool,
) -> io::Result<bool> {
    remove_path_scoped_inner(root, path, recursive, missing_ok, None, &mut |_, _, _| {})
}

/// Remove one strict descendant after checking the opened root and target against captured identities.
///
/// The root identity is checked on the opened capability. The final target is atomically moved
/// into a private quarantine through that capability, then checked by handle before recursive
/// removal. On Windows, final directories are deleted through identity-verified, rename-locked
/// handles because cap-std's path-based open-directory removal cannot keep its handle open there.
/// A mismatched moved entry remains in quarantine and fails closed.
pub fn remove_path_scoped_owned(
    root: &Path,
    path: &Path,
    root_identity: ScopedDirectoryIdentity,
    target_identity: ScopedDirectoryIdentity,
    recursive: bool,
    missing_ok: bool,
) -> io::Result<bool> {
    remove_path_scoped_inner(
        root,
        path,
        recursive,
        missing_ok,
        Some((root_identity, target_identity)),
        &mut |_, _, _| {},
    )
}

fn remove_path_scoped_inner(
    root: &Path,
    path: &Path,
    recursive: bool,
    missing_ok: bool,
    identities: Option<(ScopedDirectoryIdentity, ScopedDirectoryIdentity)>,
    after_quarantine: &mut dyn FnMut(&Dir, &std::ffi::OsStr, &Path),
) -> io::Result<bool> {
    validate_ambient_boundary(root, path)?;

    let relative = path.strip_prefix(root).map_err(|_| {
        invalid_input(format!(
            "path {} is outside declared root {}",
            path.display(),
            root.display()
        ))
    })?;
    validate_relative_target(relative)?;

    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || std_metadata_is_symlink_or_reparse(&root_metadata) {
        return Err(invalid_input(format!(
            "declared cleanup root must be a regular directory, not symlink/reparse: {}",
            root.display()
        )));
    }

    let root_dir = Dir::open_ambient_dir(root, ambient_authority())?;
    let opened_root_file = root_dir.try_clone()?.into_std_file();
    let opened_root_metadata = opened_root_file.metadata()?;
    if !opened_root_metadata.is_dir() || std_metadata_is_symlink_or_reparse(&opened_root_metadata) {
        return Err(invalid_input(format!(
            "opened cleanup root must be a regular directory, not symlink/reparse: {}",
            root.display()
        )));
    }

    if let Some((expected_root, _)) = identities
        && !expected_root.matches_file(&opened_root_file)?
    {
        return Err(invalid_input(format!(
            "opened cleanup root identity changed: {}",
            root.display()
        )));
    }

    remove_relative_no_follow(
        root_dir,
        root,
        relative,
        recursive,
        missing_ok,
        identities.map(|(_, target)| target),
        after_quarantine,
    )
}

fn remove_relative_no_follow(
    mut parent: Dir,
    root: &Path,
    relative: &Path,
    recursive: bool,
    missing_ok: bool,
    target_identity: Option<ScopedDirectoryIdentity>,
    after_quarantine: &mut dyn FnMut(&Dir, &std::ffi::OsStr, &Path),
) -> io::Result<bool> {
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(invalid_input(format!(
                "cleanup target contains a non-normal path component: {}",
                relative.display()
            )));
        };
        let final_component = components.peek().is_none();
        if final_component {
            if let Some(expected) = target_identity {
                return remove_owned_target(
                    &parent,
                    root,
                    relative,
                    expected,
                    recursive,
                    missing_ok,
                    after_quarantine,
                );
            }
            let metadata = match parent.symlink_metadata(name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound && missing_ok => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            return remove_existing(&parent, Path::new(name), &metadata, recursive);
        }

        let child = match parent.open_dir_nofollow(name) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound && missing_ok => {
                return Ok(false);
            }
            #[cfg(windows)]
            Err(error)
                if error.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_STOPPED_ON_SYMLINK as i32) =>
            {
                // Windows refuses the no-follow open on a junction ancestor.
                // Report a typed unsafe path; never follow or remove its target.
                return Err(invalid_input(format!(
                    "cleanup ancestor is a reparse point: {} ({error})",
                    name.to_string_lossy()
                )));
            }
            Err(error) => return Err(error),
        };
        let metadata = child.dir_metadata()?;
        if metadata_is_symlink_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(invalid_input(format!(
                "cleanup ancestor must be a regular directory, not symlink/reparse: {}",
                name.to_string_lossy()
            )));
        }
        parent = child;
    }
    Err(invalid_input(
        "cleanup target must contain a final path component",
    ))
}

fn remove_owned_target(
    parent: &Dir,
    _root: &Path,
    relative: &Path,
    expected: ScopedDirectoryIdentity,
    recursive: bool,
    missing_ok: bool,
    after_quarantine: &mut dyn FnMut(&Dir, &std::ffi::OsStr, &Path),
) -> io::Result<bool> {
    let name = relative.file_name().ok_or_else(|| {
        invalid_input(format!(
            "cleanup target must contain a final path component: {}",
            relative.display()
        ))
    })?;
    match parent.symlink_metadata(name) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound && missing_ok => return Ok(false),
        Err(error) => return Err(error),
    }

    // Atomically move the observed entry into a new private directory before inspecting it.
    // A concurrent replacement at the original name can then never become the deletion target.
    let quarantine_name = create_private_quarantine(parent)?;
    let quarantine = parent.open_dir_nofollow(&quarantine_name)?;
    if let Err(error) = parent.rename(name, &quarantine, "payload") {
        let _ = parent.remove_dir(&quarantine_name);
        if error.kind() == io::ErrorKind::NotFound && missing_ok {
            return Ok(false);
        }
        return Err(error);
    }
    after_quarantine(parent, &quarantine_name, Path::new(name));

    let target = match quarantine.open_dir_nofollow("payload") {
        Ok(target) => target,
        Err(error) => {
            return Err(quarantined_identity_error(
                relative,
                &quarantine_name,
                error,
            ));
        }
    };
    let target_file = target.try_clone()?.into_std_file();
    if !expected.matches_file(&target_file)? {
        return Err(invalid_input(format!(
            "cleanup target identity changed; substituted entry preserved at {}/payload",
            quarantine_name.to_string_lossy()
        )));
    }

    #[cfg(windows)]
    {
        let quarantine_path = _root
            .join(relative.parent().unwrap_or_else(|| Path::new("")))
            .join(&quarantine_name);
        let target_path = quarantine_path.join("payload");
        let quarantine_file = quarantine.try_clone()?.into_std_file();
        let quarantine_identity = identity_from_file(&quarantine_file)?;
        drop(quarantine_file);
        drop(target_file);
        drop(target);
        drop(quarantine);

        remove_windows_owned_directory(&target_path, expected, recursive)?;
        remove_windows_owned_directory(&quarantine_path, quarantine_identity, false)?;
    }
    #[cfg(not(windows))]
    {
        if recursive {
            target.remove_open_dir_all()?;
        } else {
            target.remove_open_dir()?;
        }
        parent.remove_dir(&quarantine_name)?;
    }
    Ok(true)
}

#[cfg(windows)]
fn identity_from_file(file: &fs::File) -> io::Result<ScopedDirectoryIdentity> {
    let (volume, index, attributes) = windows_file_identity(file)?;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid_input("expected a regular directory handle"));
    }
    Ok(ScopedDirectoryIdentity { volume, index })
}

/// Delete a directory only through a Win7-compatible, identity-checked DELETE handle.
#[cfg(windows)]
fn remove_windows_owned_directory(
    path: &Path,
    expected: ScopedDirectoryIdentity,
    recursive: bool,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileDispositionInfo, OPEN_EXISTING, SetFileInformationByHandle,
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // Omitting FILE_SHARE_DELETE locks this exact directory against rename/substitution until
    // Windows marks this same object for deletion by its open handle.
    let raw_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw_handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned an owned HANDLE which this File uniquely closes.
    let handle = unsafe { fs::File::from_raw_handle(raw_handle) };
    if !expected.matches_file(&handle)? {
        return Err(invalid_input(format!(
            "directory identity changed before handle-bound removal: {}",
            path.display()
        )));
    }
    if recursive {
        remove_windows_directory_contents(path)?;
    }

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            raw_handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn remove_windows_directory_contents(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)?;
        let attributes = metadata.file_attributes();
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid_input(format!(
                    "refusing recursive cleanup of directory reparse point inside owned tree: {}",
                    child.display()
                )));
            } else {
                let identity = ScopedDirectoryIdentity::capture(&child)?;
                remove_windows_owned_directory(&child, identity, true)?;
            }
        } else {
            // remove_file unlinks a symlink/reparse file without following its destination.
            fs::remove_file(&child)?;
        }
    }
    Ok(())
}

fn create_private_quarantine(parent: &Dir) -> io::Result<std::ffi::OsString> {
    loop {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name = format!(".onec-cleanup-{}", hex::encode(random));
        #[cfg(unix)]
        let builder = {
            use cap_std::fs::DirBuilderExt as _;
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = DirBuilder::new();
        match parent.create_dir_with(&name, &builder) {
            Ok(()) => return Ok(name.into()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn quarantined_identity_error(
    relative: &Path,
    quarantine: &std::ffi::OsStr,
    source: io::Error,
) -> io::Error {
    invalid_input(format!(
        "cleanup target {} identity could not be verified; substituted entry preserved at {}/payload: {source}",
        relative.display(),
        quarantine.to_string_lossy()
    ))
}

fn validate_ambient_boundary(root: &Path, path: &Path) -> io::Result<()> {
    if root.as_os_str().is_empty() || path.as_os_str().is_empty() {
        return Err(invalid_input("root and path must be non-empty"));
    }
    if !root.is_absolute() || !path.is_absolute() {
        return Err(invalid_input(format!(
            "root and path must be absolute: root={} path={}",
            root.display(),
            path.display()
        )));
    }
    if contains_parent_component(root) || contains_parent_component(path) {
        return Err(invalid_input(
            "root and path must not contain parent-directory components",
        ));
    }
    if root.parent().is_none() {
        return Err(invalid_input(format!(
            "refusing filesystem-root cleanup boundary {}",
            root.display()
        )));
    }
    Ok(())
}

fn validate_relative_target(relative: &Path) -> io::Result<()> {
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return Err(invalid_input("refusing to remove the declared root itself"));
    }
    if relative.is_absolute() || contains_parent_component(relative) {
        return Err(invalid_input(format!(
            "cleanup target must stay relative to the declared root: {}",
            relative.display()
        )));
    }
    Ok(())
}

fn remove_existing(
    parent: &Dir,
    name: &Path,
    metadata: &Metadata,
    recursive: bool,
) -> io::Result<bool> {
    if metadata_is_symlink_or_reparse(metadata) {
        if metadata.file_type().is_symlink() {
            parent.remove_file_or_symlink(name)?;
            return Ok(true);
        }
        return Err(invalid_input(format!(
            "refusing non-symlink reparse-point cleanup target {}",
            name.display()
        )));
    }

    if metadata.is_dir() {
        if recursive {
            parent.remove_dir_all(name)?;
        } else {
            parent.remove_dir(name)?;
        }
    } else {
        parent.remove_file_or_symlink(name)?;
    }
    Ok(true)
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn metadata_is_symlink_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::OsMetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

pub(crate) fn std_metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn removes_file_empty_directory_and_recursive_directory() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");

        let file = root.join("file.txt");
        fs::write(&file, b"data").expect("file");
        assert!(remove_path_scoped(&root, &file, false, false).expect("remove file"));
        assert!(!file.exists());

        let empty = root.join("empty");
        fs::create_dir(&empty).expect("empty");
        assert!(remove_path_scoped(&root, &empty, false, false).expect("remove empty"));
        assert!(!empty.exists());

        let tree = root.join("tree");
        fs::create_dir_all(tree.join("nested")).expect("tree");
        fs::write(tree.join("nested/payload"), b"data").expect("payload");
        assert!(remove_path_scoped(&root, &tree, true, false).expect("remove tree"));
        assert!(!tree.exists());
        assert!(root.is_dir());
    }

    #[test]
    fn identity_scoped_removal_rejects_substituted_root_and_target_at_capability_boundary() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");
        let target = root.join("database");
        fs::create_dir(&target).expect("target");
        fs::write(target.join("1Cv8.1CD"), b"owned database").expect("database marker");
        let root_identity = ScopedDirectoryIdentity::capture(&root).expect("root identity");
        let target_identity = ScopedDirectoryIdentity::capture(&target).expect("target identity");

        let displaced_root = base.path().join("displaced-owned");
        fs::rename(&root, &displaced_root).expect("displace owned root");
        fs::create_dir(&root).expect("substitute owned root");
        let replacement = root.join("database");
        fs::create_dir(&replacement).expect("substitute target");
        fs::write(replacement.join("keep"), b"unrelated").expect("replacement sentinel");

        let error = remove_path_scoped_owned(
            &root,
            &replacement,
            root_identity,
            target_identity,
            true,
            false,
        )
        .expect_err("substituted root must fail before target removal");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            fs::read(replacement.join("keep")).expect("replacement survives"),
            b"unrelated"
        );
        assert!(displaced_root.join("database/1Cv8.1CD").is_file());
    }

    #[test]
    fn identity_scoped_removal_rejects_target_substitution_after_identity_capture() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");
        let target = root.join("database");
        fs::create_dir(&target).expect("target");
        fs::write(target.join("1Cv8.1CD"), b"owned database").expect("database marker");
        let root_identity = ScopedDirectoryIdentity::capture(&root).expect("root identity");
        let target_identity = ScopedDirectoryIdentity::capture(&target).expect("target identity");

        let displaced = root.join("displaced-database");
        fs::rename(&target, &displaced).expect("displace original target");
        fs::create_dir(&target).expect("substitute target");
        fs::write(target.join("keep"), b"unrelated").expect("replacement sentinel");

        let error =
            remove_path_scoped_owned(&root, &target, root_identity, target_identity, true, false)
                .expect_err("target substituted after identity capture must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let quarantine = fs::read_dir(&root)
            .expect("owned root")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".onec-cleanup-"))
            })
            .expect("preserved quarantine");
        assert_eq!(
            fs::read(quarantine.join("payload/keep")).expect("replacement survives"),
            b"unrelated"
        );
        assert!(displaced.join("1Cv8.1CD").is_file());
    }

    #[test]
    fn identity_scoped_removal_preserves_substitution_during_quarantine() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");
        let target = root.join("database");
        fs::create_dir(&target).expect("target");
        fs::write(target.join("1Cv8.1CD"), b"owned database").expect("database marker");
        let root_identity = ScopedDirectoryIdentity::capture(&root).expect("root identity");
        let target_identity = ScopedDirectoryIdentity::capture(&target).expect("target identity");
        let mut quarantine_path = None;

        let error = remove_path_scoped_inner(
            &root,
            &target,
            true,
            false,
            Some((root_identity, target_identity)),
            &mut |parent, quarantine_name, target_name| {
                let quarantine = parent
                    .open_dir_nofollow(quarantine_name)
                    .expect("open private quarantine");
                quarantine
                    .rename("payload", parent, target_name)
                    .expect("restore original before substituting quarantined entry");
                quarantine
                    .create_dir("payload")
                    .expect("substitute quarantined entry");
                let path = root.join(quarantine_name).join("payload");
                fs::write(path.join("keep"), b"substitute").expect("substitute sentinel");
                quarantine_path = Some(path);
            },
        )
        .expect_err("identity mismatch after quarantine must fail closed");

        assert!(
            error
                .to_string()
                .contains("cleanup target identity changed"),
            "{error}"
        );
        assert!(
            target.join("1Cv8.1CD").is_file(),
            "original target is preserved"
        );
        let quarantine_path = quarantine_path.expect("quarantined substitute path");
        assert_eq!(
            fs::read(quarantine_path.join("keep")).expect("substitute survives"),
            b"substitute"
        );
    }

    #[cfg(windows)]
    #[test]
    fn identity_scoped_windows_cleanup_removes_target_and_quarantine_by_handle() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");
        let parent = root.join("nested-parent");
        fs::create_dir(&parent).expect("parent");
        let target = parent.join("database");
        fs::create_dir_all(target.join("nested/deeper")).expect("nested target");
        fs::write(target.join("nested/deeper/payload"), b"owned").expect("payload");
        let root_identity = ScopedDirectoryIdentity::capture(&root).expect("root identity");
        let target_identity = ScopedDirectoryIdentity::capture(&target).expect("target identity");

        assert!(
            remove_path_scoped_owned(&root, &target, root_identity, target_identity, true, false,)
                .expect("handle-bound cleanup")
        );
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&parent).expect("parent entries").count(), 0);
    }

    #[test]
    fn rejects_empty_relative_root_self_outside_parent_and_filesystem_root() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        let outside = base.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");

        for (declared_root, target, label) in [
            (PathBuf::new(), root.clone(), "empty root"),
            (root.clone(), PathBuf::new(), "empty target"),
            (PathBuf::from("relative"), root.clone(), "relative root"),
            (root.clone(), PathBuf::from("relative"), "relative target"),
            (root.clone(), root.clone(), "root self"),
            (root.clone(), outside.clone(), "outside"),
            (
                root.clone(),
                root.join("child").join("..").join("escape"),
                "parent",
            ),
        ] {
            let error = remove_path_scoped(&declared_root, &target, true, false).expect_err(label);
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{label}");
        }

        let filesystem_root = root.ancestors().last().expect("filesystem root");
        let error = remove_path_scoped(
            filesystem_root,
            &filesystem_root.join("must-not-remove"),
            true,
            true,
        )
        .expect_err("filesystem root");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_target_preserves_strict_and_missing_ok_semantics() {
        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        fs::create_dir(&root).expect("root");
        let missing = root.join("missing/deeper");

        let error = remove_path_scoped(&root, &missing, true, false).expect_err("strict missing");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!remove_path_scoped(&root, &missing, true, true).expect("missing ok"));
    }

    #[cfg(unix)]
    #[test]
    fn removes_final_symlinks_without_following_and_rejects_ancestor_escape() {
        use std::os::unix::fs::symlink;

        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        let outside = base.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        let inside_file = root.join("inside.txt");
        fs::write(&inside_file, b"inside").expect("inside");

        let safe = root.join("safe-link");
        symlink("inside.txt", &safe).expect("safe symlink");
        assert!(remove_path_scoped(&root, &safe, false, false).expect("remove safe symlink"));
        assert!(!safe.exists());
        assert!(inside_file.exists());

        let dangling = root.join("dangling-link");
        symlink("missing.txt", &dangling).expect("dangling symlink");
        assert!(remove_path_scoped(&root, &dangling, false, false).expect("remove dangling"));
        assert!(fs::symlink_metadata(&dangling).is_err());

        let survivor = outside.join("survivor");
        fs::write(&survivor, b"outside").expect("outside file");

        let final_escape = root.join("final-escape-link");
        symlink(&outside, &final_escape).expect("final escape symlink");
        assert!(remove_path_scoped(&root, &final_escape, true, false).expect("remove final link"));
        assert!(!final_escape.exists());
        assert!(survivor.exists());

        let sibling = root.join("sibling");
        fs::create_dir(&sibling).expect("sibling");
        let sibling_survivor = sibling.join("survivor");
        fs::write(&sibling_survivor, b"sibling").expect("sibling file");
        let in_root_alias = root.join("in-root-alias");
        symlink("sibling", &in_root_alias).expect("in-root ancestor symlink");
        let error = remove_path_scoped(&root, &in_root_alias.join("survivor"), false, false)
            .expect_err("in-root ancestor symlink must be rejected");
        assert!(!error.to_string().is_empty());
        assert_eq!(
            fs::read(&sibling_survivor).expect("sibling survivor"),
            b"sibling"
        );

        let ancestor_escape = root.join("ancestor-escape");
        symlink(&outside, &ancestor_escape).expect("ancestor escape symlink");
        let error = remove_path_scoped(&root, &ancestor_escape.join("survivor"), false, false)
            .expect_err("ancestor escape rejected");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::NotFound
                    | io::ErrorKind::NotADirectory
            ),
            "{error:?}"
        );
        assert!(survivor.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_final_directory_symlink_is_removed_without_following_target() {
        use std::os::windows::fs::symlink_dir;

        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        let outside = base.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        let survivor = outside.join("survivor");
        fs::write(&survivor, b"outside").expect("outside file");

        let link = root.join("outside-link");
        match symlink_dir(&outside, &link) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ) || error.raw_os_error() == Some(1314) =>
            {
                eprintln!("skipping symlink regression: {error}");
                return;
            }
            Err(error) => panic!("create directory symlink: {error}"),
        }

        assert!(remove_path_scoped(&root, &link, true, false).expect("remove final symlink"));
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read(&survivor).expect("outside survivor"), b"outside");
    }

    #[cfg(windows)]
    #[test]
    fn windows_final_directory_junction_is_removed_without_following_target() {
        use std::process::Command;

        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        let outside = base.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        let survivor = outside.join("survivor");
        fs::write(&survivor, b"outside").expect("outside file");

        let junction = root.join("outside-junction");
        let output = Command::new("cmd.exe")
            .args([
                "/D",
                "/C",
                "mklink",
                "/J",
                junction.to_string_lossy().as_ref(),
                outside.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("launch mklink");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

        let metadata = fs::symlink_metadata(&junction).expect("junction metadata");
        assert_ne!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0,
            "fixture must be a reparse point"
        );

        assert!(
            remove_path_scoped(&root, &junction, true, false)
                .expect("remove final junction without following")
        );
        assert!(fs::symlink_metadata(&junction).is_err());
        assert_eq!(fs::read(&survivor).expect("outside survivor"), b"outside");
    }

    #[cfg(windows)]
    #[test]
    fn windows_ancestor_junction_escape_is_rejected() {
        use std::process::Command;

        let base = tempdir().expect("base");
        let root = base.path().join("owned");
        let outside = base.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        let survivor = outside.join("survivor");
        fs::write(&survivor, b"outside").expect("outside file");

        let junction = root.join("ancestor-junction");
        let output = Command::new("cmd.exe")
            .args([
                "/D",
                "/C",
                "mklink",
                "/J",
                junction.to_string_lossy().as_ref(),
                outside.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("launch mklink");
        assert!(
            output.status.success(),
            "mklink /J failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let error = remove_path_scoped(&root, &junction.join("survivor"), false, false)
            .expect_err("ancestor junction escape must be rejected");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::InvalidInput
                    | io::ErrorKind::NotFound
            ),
            "{error:?}"
        );
        assert_eq!(fs::read(&survivor).expect("outside survivor"), b"outside");
        assert!(
            junction.exists(),
            "rejected ancestor junction must remain intact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_declared_root() {
        use std::os::unix::fs::symlink;

        let base = tempdir().expect("base");
        let actual = base.path().join("actual");
        fs::create_dir(&actual).expect("actual");
        let root = base.path().join("root-link");
        symlink(&actual, &root).expect("root symlink");

        let error = remove_path_scoped(&root, &root.join("child"), true, true)
            .expect_err("symlink root rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
