//! Narrow runtime-neutral filesystem preparation helpers for ordinary paths.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Canonicalizes an existing or future path through its nearest existing ancestor.
///
/// Relative inputs are first anchored to the current directory. Existing components are resolved
/// by the filesystem, so symlink and `..` semantics are preserved. Missing trailing normal
/// components are appended to the canonical existing ancestor without creating them. A future
/// path that would require resolving `..` through a missing component is rejected rather than
/// guessed by lexical normalization.
///
/// # Errors
///
/// Returns an I/O error when the current directory or an existing ancestor cannot be resolved.
pub fn canonicalize_future_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    #[cfg(windows)]
    reject_parent_after_missing_component(&absolute)?;
    let mut ancestor = absolute.as_path();
    let mut suffix = Vec::new();

    loop {
        match fs::canonicalize(ancestor) {
            Ok(mut canonical) => {
                for component in suffix.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "cannot resolve existing ancestor for future path {}",
                            absolute.display()
                        ),
                    )
                })?;
                suffix.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "cannot resolve existing ancestor for future path {}",
                            absolute.display()
                        ),
                    )
                })?;
            }
            Err(source) => return Err(source),
        }
    }
}

// Windows path APIs normalize `normal\\..` before checking whether `normal` exists. Check each
// normal prefix first so a future path never guesses the result of traversing through a missing
// component. Existing components are still resolved by `canonicalize` below.
#[cfg(windows)]
fn reject_parent_after_missing_component(path: &Path) -> io::Result<()> {
    let mut prefix = PathBuf::new();
    let mut missing_component = false;

    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                prefix.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                prefix.push(name);
                if !missing_component {
                    match fs::symlink_metadata(&prefix) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            missing_component = true;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            std::path::Component::ParentDir => {
                if missing_component {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "cannot resolve parent traversal through a missing component in future path {}",
                            path.display()
                        ),
                    ));
                }
                prefix.push(component.as_os_str());
            }
        }
    }
    Ok(())
}

/// Small filesystem preparation operations shared by path-owning domain crates.
pub trait PathFsExt {
    /// Ensures that this path exists as a directory, creating missing parents as needed.
    fn ensure_directory(&self) -> io::Result<()>;

    /// Ensures that this path's non-empty parent directory exists.
    fn ensure_parent_directory(&self) -> io::Result<()>;
}

impl PathFsExt for Path {
    fn ensure_directory(&self) -> io::Result<()> {
        fs::create_dir_all(self)
    }

    fn ensure_parent_directory(&self) -> io::Result<()> {
        if let Some(parent) = self.parent()
            && !parent.as_os_str().is_empty()
        {
            parent.ensure_directory()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parent_directory_preparation_creates_only_the_parent() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("nested").join("artifact.cf");

        output
            .as_path()
            .ensure_parent_directory()
            .expect("ensure parent");

        assert!(root.path().join("nested").is_dir());
        assert!(!output.exists());
    }

    #[test]
    fn directory_preparation_is_idempotent() {
        let root = tempdir().expect("tempdir");
        let directory = root.path().join("nested").join("directory");

        directory.as_path().ensure_directory().expect("first");
        directory.as_path().ensure_directory().expect("second");

        assert!(directory.is_dir());
    }

    #[test]
    fn future_path_canonicalizes_existing_ancestor_without_creating_suffix() {
        let root = tempdir().expect("tempdir");
        let existing = root.path().join("existing");
        fs::create_dir(&existing).expect("existing directory");
        let future = existing.join("nested").join("artifact.cf");

        let canonical = canonicalize_future_path(&future).expect("canonical future path");

        assert_eq!(
            canonical,
            fs::canonicalize(&existing)
                .expect("canonical existing directory")
                .join("nested")
                .join("artifact.cf")
        );
        assert!(!future.exists());
    }

    #[test]
    fn future_path_rejects_parent_traversal_through_a_missing_component() {
        let root = tempdir().expect("tempdir");
        let ambiguous = root.path().join("missing").join("..").join("future");

        let error = canonicalize_future_path(&ambiguous)
            .expect_err("missing/.. cannot be resolved safely before missing exists");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!root.path().join("future").exists());
    }

    #[cfg(unix)]
    #[test]
    fn future_path_aliases_share_one_canonical_identity_before_creation() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("tempdir");
        let physical = root.path().join("physical");
        fs::create_dir(&physical).expect("physical directory");
        let alias = root.path().join("alias");
        symlink(&physical, &alias).expect("parent alias");

        assert_eq!(
            canonicalize_future_path(&physical.join("future")).expect("physical identity"),
            canonicalize_future_path(&alias.join("future")).expect("alias identity")
        );
    }

    #[cfg(unix)]
    #[test]
    fn regression_inv_134_path_preparation_preserves_non_utf8_components() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = tempdir().expect("tempdir");
        let directory = root
            .path()
            .join(OsString::from_vec(b"non-utf8-\xff".to_vec()));

        directory.as_path().ensure_directory().expect("non-utf8");

        assert!(directory.is_dir());
    }
}
