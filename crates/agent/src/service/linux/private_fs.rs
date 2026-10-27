use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) fn canonical_private_dir(path: &Path, uid: u32) -> io::Result<PathBuf> {
    let requested = fs::symlink_metadata(path)?;
    if requested.file_type().is_symlink() {
        return Err(invalid("install root must not be a symlink"));
    }
    let canonical = path.canonicalize()?;
    let m = fs::symlink_metadata(&canonical)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(invalid(
            "install root must be an existing private directory owned by the current user",
        ));
    }
    Ok(canonical)
}
pub(super) fn canonical_regular(path: &Path, uid: u32) -> io::Result<PathBuf> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o022 != 0 {
        return Err(invalid(
            "service input must be a regular current-user-owned file without symlinks or group/world write access",
        ));
    }
    path.canonicalize()
}
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut b = [0; 64 * 1024];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex(&h.finalize()))
}
pub(super) fn busy(ids: &[String]) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
            "Agent lifecycle deferred: {} durable jobs are Prepared, Running or Interrupted; inspect jobs before stopping or removing service",
            ids.len()
        ),
    )
}
pub(super) fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
