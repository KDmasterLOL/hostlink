use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use super::{HostReadiness, block};

pub(super) fn string_field(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;

pub(super) fn valid_host_pin(pin: &str) -> bool {
    let fields: Vec<_> = pin.split_ascii_whitespace().collect();
    if !(2..=3).contains(&fields.len()) {
        return false;
    }
    if !fields[0].starts_with("ssh-") && !fields[0].starts_with("ecdsa-") {
        return false;
    }
    russh::keys::parse_public_key_base64(fields[1])
        .is_ok_and(|key| key.algorithm().to_string() == fields[0])
}

pub(super) fn require_owned_path(
    value: &Value,
    field: &str,
    config: &Path,
    regular_file: bool,
    report: &mut HostReadiness,
) {
    let Some(path) = string_field(value, field) else {
        block(
            report,
            if field == "jobs_root" {
                "desired Agent jobs root is missing"
            } else {
                "required desired key path is missing"
            },
        );
        return;
    };
    let path = PathBuf::from(path);
    let resolved = if path.is_absolute() {
        path
    } else {
        config.parent().unwrap_or(Path::new(".")).join(path)
    };
    if has_symlink_component(&resolved) {
        block(report, "required desired path traverses a symlink");
        return;
    }
    let metadata = match fs::symlink_metadata(&resolved) {
        Ok(metadata) if !metadata.file_type().is_symlink() => metadata,
        _ => {
            block(
                report,
                "required desired path is missing, unreadable, or a symlink",
            );
            return;
        }
    };
    if (regular_file && !metadata.is_file()) || (!regular_file && !metadata.is_dir()) {
        block(report, "required desired path has the wrong file type");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            block(report, "desired path is not owned by the preflight user");
        }
        if regular_file && metadata.mode() & 0o077 != 0 {
            block(
                report,
                "desired private key file permissions are broader than owner-only",
            );
        } else if !regular_file && metadata.mode() & 0o077 != 0 {
            block(
                report,
                "desired Agent root permissions are broader than owner-only",
            );
        }
    }
    #[cfg(windows)]
    if !regular_file {
        report
            .review
            .push("desired Agent root owner and ACL must be verified on Windows".into());
    }
}

fn has_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

pub(super) fn read_json(path: &Path) -> Result<Value, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cannot read supplied snapshot")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("supplied snapshots must be bounded regular files, not symlinks");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|_| "cannot read supplied snapshot")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot read supplied snapshot")?;
    if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err("supplied snapshots must be bounded regular files");
    }
    read_json_file(file)
}

fn read_json_file(mut file: File) -> Result<Value, &'static str> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read supplied snapshot")?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err("supplied snapshot exceeds the size limit");
    }
    serde_json::from_slice(&bytes).map_err(|_| "supplied snapshot is not valid JSON")
}
