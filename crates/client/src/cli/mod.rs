//! Private command-line interface implementation for the HostLink binary.

mod args;
mod commands;
#[cfg(test)]
mod tests;

pub(super) const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

use hostlink::HostSpec;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub(super) async fn run() -> Result<i32, Box<dyn std::error::Error>> {
    use clap::Parser;
    commands::run(args::Cli::parse()).await
}

pub(super) fn load_host_spec(path: &Path) -> io::Result<HostSpec> {
    let bytes = read_existing_file(path, MAX_CONFIG_BYTES)?;
    let mut config: HostSpec = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    if config.identity.is_relative() {
        config.identity = base.join(config.identity);
    }
    if let Some(gateway) = &mut config.gateway {
        if gateway.identity.is_relative() {
            gateway.identity = base.join(&gateway.identity);
        }
        for route in &mut gateway.alternates {
            if route.identity.is_relative() {
                route.identity = base.join(&route.identity);
            }
        }
    }
    Ok(config)
}

pub(super) fn read_existing_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source must be a bounded regular file, not a symlink",
        ));
    }
    read_limited(File::open(path)?, max_bytes)
}

pub(super) fn read_limited(mut reader: impl Read, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub(super) fn create_new_output(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        if let Err(cleanup) = fs::remove_file(path) {
            return Err(io::Error::other(format!(
                "SFTP local output write failed: {error}; owned partial file cleanup failed: {cleanup}",
            )));
        }
        return Err(error);
    }
    Ok(())
}
