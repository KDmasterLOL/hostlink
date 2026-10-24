//! Typed filesystem directories with explicit preparation operations.

use super::path_io_error::PathIoError;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A filesystem path that was verified to be a directory when acquired.
///
/// Directory state can change after construction. In particular, an empty directory returned by
/// [`Directory::ensure_empty`] is only observed to be empty at that moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory(PathBuf);

/// Failure while ensuring that a path names an empty directory.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// Filesystem inspection or creation failed at the associated path.
    #[error(transparent)]
    Io(#[from] PathIoError),
    /// The requested path names an existing directory that contains at least one entry.
    #[error("directory is not empty: {path}", path = path.display())]
    NotEmpty {
        /// Path observed to contain an entry.
        path: PathBuf,
    },
    /// The requested path exists but does not name a directory.
    #[error("path is not a directory: {path}", path = path.display())]
    NotDirectory {
        /// Path observed not to be a directory.
        path: PathBuf,
    },
}

impl Directory {
    /// Opens an existing directory without creating or changing filesystem state.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::NotDirectory`] when the path exists as a non-directory,
    /// [`DirectoryError::Io`] when the path is missing or cannot be inspected.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref();
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(Self(path.to_path_buf())),
            Ok(_) => Err(DirectoryError::NotDirectory {
                path: path.to_path_buf(),
            }),
            Err(source) if source.kind() == io::ErrorKind::NotADirectory => {
                Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                })
            }
            #[cfg(windows)]
            Err(source)
                if source.kind() == io::ErrorKind::PermissionDenied
                    && has_non_directory_ancestor(path) =>
            {
                Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                })
            }
            Err(source) => Err(PathIoError::new(path, source).into()),
        }
    }

    /// Creates missing directory components and returns the resulting directory.
    ///
    /// Existing directories are accepted regardless of their contents.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::NotDirectory`] when the path or one of its components is a
    /// non-directory, and [`DirectoryError::Io`] when inspection or creation fails.
    pub fn ensure(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref();
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(Self(path.to_path_buf())),
            Ok(_) => Err(DirectoryError::NotDirectory {
                path: path.to_path_buf(),
            }),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                if let Err(source) = fs::create_dir_all(path) {
                    if let Ok(metadata) = fs::metadata(path)
                        && metadata.is_dir()
                    {
                        return Ok(Self(path.to_path_buf()));
                    }
                    if source.kind() == io::ErrorKind::NotADirectory {
                        return Err(DirectoryError::NotDirectory {
                            path: path.to_path_buf(),
                        });
                    }
                    #[cfg(windows)]
                    if has_non_directory_ancestor(path) {
                        return Err(DirectoryError::NotDirectory {
                            path: path.to_path_buf(),
                        });
                    }
                    return Err(PathIoError::new(path, source).into());
                }
                Ok(Self(path.to_path_buf()))
            }
            Err(source) if source.kind() == io::ErrorKind::NotADirectory => {
                Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                })
            }
            Err(source) => Err(PathIoError::new(path, source).into()),
        }
    }

    /// Creates a missing directory tree or verifies that the existing directory is empty.
    ///
    /// Emptiness is observational: this method neither reserves the directory nor prevents later
    /// writes by other processes.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::NotEmpty`] for a non-empty directory,
    /// [`DirectoryError::NotDirectory`] when the path exists as a non-directory, and
    /// [`DirectoryError::Io`] when filesystem access or creation fails.
    pub fn ensure_empty(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let path = path.as_ref();
        match fs::metadata(path) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                if let Err(source) = fs::create_dir_all(path) {
                    // A concurrent creator can win with a file between metadata and creation.
                    if let Ok(metadata) = fs::metadata(path)
                        && !metadata.is_dir()
                    {
                        return Err(DirectoryError::NotDirectory {
                            path: path.to_path_buf(),
                        });
                    }
                    if source.kind() == io::ErrorKind::NotADirectory {
                        return Err(DirectoryError::NotDirectory {
                            path: path.to_path_buf(),
                        });
                    }
                    #[cfg(windows)]
                    if has_non_directory_ancestor(path) {
                        return Err(DirectoryError::NotDirectory {
                            path: path.to_path_buf(),
                        });
                    }
                    return Err(PathIoError::new(path, source).into());
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotADirectory => {
                return Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                });
            }
            #[cfg(windows)]
            Err(source)
                if source.kind() == io::ErrorKind::PermissionDenied
                    && has_non_directory_ancestor(path) =>
            {
                return Err(DirectoryError::NotDirectory {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => return Err(PathIoError::new(path, source).into()),
        }

        let mut entries = fs::read_dir(path).map_err(|source| PathIoError::new(path, source))?;
        if entries
            .next()
            .transpose()
            .map_err(|source| PathIoError::new(path, source))?
            .is_some()
        {
            return Err(DirectoryError::NotEmpty {
                path: path.to_path_buf(),
            });
        }

        Ok(Self(path.to_path_buf()))
    }

    /// Returns the directory's native path without changing its filesystem state.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[cfg(windows)]
fn has_non_directory_ancestor(path: &Path) -> bool {
    let mut ancestor = path.parent();
    while let Some(candidate) = ancestor {
        match fs::metadata(candidate) {
            Ok(metadata) => return !metadata.is_dir(),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                ancestor = candidate.parent();
            }
            Err(_) => return false,
        }
    }
    false
}

impl AsRef<Path> for Directory {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

#[cfg(test)]
mod tests {
    use super::{Directory, DirectoryError};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn open_requires_an_existing_directory_and_has_no_creation_side_effect() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("missing");

        let error = Directory::open(&path).expect_err("missing directory");

        assert!(matches!(error, DirectoryError::Io(_)));
        assert!(!path.exists());
    }

    #[test]
    fn open_accepts_existing_non_empty_directory() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("output");
        fs::create_dir(&path).expect("create directory");
        fs::write(path.join("existing.xml"), b"xml").expect("create entry");

        let directory = Directory::open(&path).expect("existing directory");

        assert_eq!(directory.as_path(), path);
    }

    #[test]
    fn ensure_creates_missing_components_and_accepts_existing_contents() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("nested").join("output");

        let directory = Directory::ensure(&path).expect("create directory tree");
        fs::write(path.join("existing.xml"), b"xml").expect("create entry");
        let existing = Directory::ensure(&path).expect("existing non-empty directory");

        assert_eq!(directory.as_path(), path);
        assert_eq!(existing.as_path(), path);
    }

    #[test]
    fn ensures_missing_directory_and_parent_directories() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("nested").join("output");

        let directory = Directory::ensure_empty(&path).expect("create empty directory");

        assert_eq!(directory.as_path(), path);
        assert!(path.is_dir());
    }

    #[test]
    fn accepts_existing_empty_directory() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("output");
        fs::create_dir(&path).expect("create directory");

        let directory = Directory::ensure_empty(&path).expect("existing empty directory");

        assert_eq!(directory.as_path(), path);
    }

    #[test]
    fn rejects_non_empty_directory_with_its_path() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("output");
        fs::create_dir(&path).expect("create directory");
        fs::write(path.join("existing.xml"), b"xml").expect("create entry");

        let error = Directory::ensure_empty(&path).expect_err("non-empty directory");

        assert!(
            matches!(error, DirectoryError::NotEmpty { path: error_path } if error_path == path)
        );
    }

    #[test]
    fn rejects_non_directory_with_its_path() {
        let root = tempdir().expect("temporary root");
        let path = root.path().join("output");
        fs::write(&path, b"file").expect("create file");

        let error = Directory::ensure_empty(&path).expect_err("file is not a directory");

        assert!(
            matches!(error, DirectoryError::NotDirectory { path: ref error_path } if error_path == &path),
            "unexpected classification: {error:?}"
        );
    }

    #[test]
    fn rejects_path_below_non_directory_with_typed_failure() {
        let root = tempdir().expect("temporary root");
        let parent = root.path().join("file");
        fs::write(&parent, b"file").expect("create file");
        let path = parent.join("output");

        let error = Directory::ensure_empty(&path).expect_err("parent is not a directory");

        assert!(
            matches!(error, DirectoryError::NotDirectory { path: error_path } if error_path == path)
        );
    }
}
