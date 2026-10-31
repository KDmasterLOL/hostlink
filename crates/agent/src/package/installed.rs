//! Exact installed identity; format 2 metadata travels atomically inside nonsecret bin.

use super::{
    EXECUTABLE_BASE, INSTALL_METADATA, InstallMetadata, MAX_MANIFEST_BYTES, invalid, package_files,
    validate_sha256,
};
use crate::agent_files::{file_identities, is_reparse_point};
use crate::package::{supported_targets, target_matches_runtime};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::Path,
};

pub(crate) fn read_installed(root: &Path) -> io::Result<InstallMetadata> {
    let path = root.join("bin").join(INSTALL_METADATA);
    let metadata: InstallMetadata = serde_json::from_slice(&read_regular(&path)?)?;
    if metadata.format != 2 {
        return Err(invalid("installed Agent metadata must have format 2"));
    }
    if !supported_targets().contains(&metadata.target.as_str())
        || !target_matches_runtime(&metadata.target)
    {
        return Err(invalid(
            "installed Agent target does not match this runtime",
        ));
    }
    validate_installed(&root.join("bin"), &metadata, &metadata.target)?;
    Ok(metadata)
}

pub(crate) fn read_regular(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse_point(&metadata) || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(invalid("Agent metadata is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("Agent metadata exceeds its size limit"));
    }
    Ok(bytes)
}

pub(crate) fn validate_installed(
    bin: &Path,
    metadata: &InstallMetadata,
    target: &str,
) -> io::Result<()> {
    if metadata.format != 2 || metadata.target != target {
        return Err(invalid(
            "installed Agent metadata has a different format or target",
        ));
    }
    semver::Version::parse(&metadata.installed_version).map_err(io::Error::other)?;
    validate_sha256(&metadata.installed_package_sha256)?;
    validate_directory(bin)?;
    let mut expected = package_files(target).into_iter().collect::<BTreeSet<_>>();
    expected.insert(INSTALL_METADATA.into());
    let actual = fs::read_dir(bin)?
        .map(|entry| {
            let entry = entry?;
            let info = fs::symlink_metadata(entry.path())?;
            if !info.is_file() || is_reparse_point(&info) {
                return Err(invalid("Agent bin contains a non-regular file"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Agent bin filename is not UTF-8"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    if actual != expected
        || file_identities(bin, &package_files(target))? != metadata.installed_files
    {
        return Err(invalid(
            "installed Agent files differ from their exact identity metadata",
        ));
    }
    let executable = if target.contains("windows") {
        "hostlink-agent.exe"
    } else {
        EXECUTABLE_BASE
    };
    verify_executable(&bin.join(executable))?;
    Ok(())
}

fn validate_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(invalid("Agent bin is not a real directory"));
    }
    Ok(())
}

/// Service registration validates its runnable file without imposing data-file ACLs on bin.
pub(crate) fn verify_executable(path: &Path) -> io::Result<()> {
    validate_directory(
        path.parent()
            .ok_or_else(|| invalid("executable has no parent"))?,
    )?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(invalid("installed Agent executable is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o100 == 0 {
            return Err(invalid("installed Agent is not owner-executable"));
        }
    }
    Ok(())
}
