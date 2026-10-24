//! Non-Windows lifecycle stubs.

use super::{ServiceRuntimeStatus, io};
use std::path::{Path, PathBuf};

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows service management is available only in Windows builds",
    )
}

pub(super) fn install(_config: &Path, _start: bool) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn start() -> io::Result<ServiceRuntimeStatus> {
    Err(unsupported())
}

pub(super) fn stop() -> io::Result<ServiceRuntimeStatus> {
    Err(unsupported())
}

pub(super) fn status() -> io::Result<ServiceRuntimeStatus> {
    Err(unsupported())
}

pub(super) fn uninstall(_stop: bool) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn dispatch(_config: PathBuf) -> io::Result<()> {
    Err(unsupported())
}
