//! Atomic SSH file publication and platform-specific private-file permissions.

use super::*;

pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    onec_core::write_private_file_atomically(path, bytes).map_err(|source| io_error(path, source))
}
