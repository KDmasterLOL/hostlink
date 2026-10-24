use std::io;
use std::path::{Path, PathBuf};

/// Filesystem I/O failure bound to the exact path involved in the operation.
///
/// This neutral source keeps path identity and the original io::Error structural so domain
/// crates can add semantic context without re-declaring the same fields or flattening the OS
/// failure into text.
#[derive(Debug, thiserror::Error)]
#[error("I/O error at {path}: {source}", path = path.display())]
pub struct PathIoError {
    path: PathBuf,
    #[source]
    source: io::Error,
}

impl PathIoError {
    /// Creates a path-aware I/O source while preserving native OS path representation.
    pub fn new(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self {
            path: path.into(),
            source,
        }
    }

    /// Returns the exact path associated with the failed operation.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the original operating-system I/O error.
    pub fn io_error(&self) -> &io::Error {
        &self.source
    }

    /// Consumes this value and returns the original operating-system I/O error.
    pub fn into_io_error(self) -> io::Error {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::PathIoError;
    use std::error::Error as _;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn path_io_error_preserves_path_and_os_source() {
        let path = PathBuf::from("state").join("ibases.v8i");
        let error = PathIoError::new(&path, io::Error::from_raw_os_error(5));

        assert_eq!(error.path(), path);
        assert_eq!(error.io_error().raw_os_error(), Some(5));
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("typed io source");
        assert_eq!(source.raw_os_error(), Some(5));
        assert_eq!(error.into_io_error().raw_os_error(), Some(5));
    }

    #[cfg(unix)]
    #[test]
    fn path_io_error_preserves_non_utf8_path_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let path = PathBuf::from(OsString::from_vec(b"state-\xff".to_vec()));
        let error = PathIoError::new(path.clone(), io::Error::other("fixture"));

        assert_eq!(
            error.path().as_os_str().as_bytes(),
            path.as_os_str().as_bytes()
        );
    }
}
