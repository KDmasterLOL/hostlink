//! Runtime-neutral filesystem primitives and their security boundaries.

mod atomic_file;
mod directory;
mod file_io;
mod io_util;
mod path_fs;
mod path_io_error;
mod private_file;
mod regular_file;
mod scoped_fs;

pub use atomic_file::{
    copy_file_atomically, copy_file_atomically_new, move_directory_atomically_new,
    move_file_atomically, replace_file_atomically, write_file_atomically,
    write_file_atomically_new, write_private_file_atomically,
};
pub use directory::{Directory, DirectoryError};
pub use file_io::{
    create_new_private_file, create_private_directory, ensure_private_directory,
    write_new_private_bytes,
};
pub use io_util::{
    FileDigest, compact_file_tail_bounded, digest_file, read_file_bounded, read_file_tail_bounded,
    sha256_file,
};
pub use path_fs::{PathFsExt, canonicalize_future_path};
pub use path_io_error::PathIoError;
pub use private_file::{
    PrivatePathError, PrivatePathResult, restrict_private_directory, restrict_private_file,
    validate_private_file,
};
pub use regular_file::RegularFile;
pub use scoped_fs::{ScopedDirectoryIdentity, remove_path_scoped, remove_path_scoped_owned};

pub(crate) use file_io::{
    open_private_append, open_private_read_existing, open_private_read_write_existing,
    validate_private_parent,
};
