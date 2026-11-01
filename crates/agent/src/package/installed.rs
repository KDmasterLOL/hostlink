//! Read one release manifest without reformatting it during installation.

use super::{
    ARCHIVE_DIGEST, EXECUTABLE_BASE, MAX_MANIFEST_BYTES, PACKAGE_MANIFEST, PackageManifest,
    invalid, package_files, supported_targets, target_matches_runtime,
};
use crate::agent_files::{file_identities, is_reparse_point};
use hex::FromHex;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::Path,
};

/// The source manifest remains verbatim in bin; the independently pinned archive
/// checksum is stored alongside it after extraction (it cannot hash itself in ZIP).
pub(crate) fn read_installed(root: &Path) -> io::Result<(PackageManifest, [u8; 32])> {
    let bin = root.join("bin");
    let manifest: PackageManifest =
        serde_json::from_slice(&read_regular(&bin.join(PACKAGE_MANIFEST))?)?;
    if !supported_targets().contains(&manifest.target.as_str())
        || !target_matches_runtime(&manifest.target)
    {
        return Err(invalid(
            "installed Agent target does not match this runtime",
        ));
    }
    let archive_sha256 = <[u8; 32]>::from_hex(read_regular(&bin.join(ARCHIVE_DIGEST))?)
        .map_err(|_| invalid("installed archive SHA-256 must contain 32 hexadecimal bytes"))?;
    validate_installed(&bin, &manifest, &manifest.target)?;
    Ok((manifest, archive_sha256))
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
    manifest: &PackageManifest,
    target: &str,
) -> io::Result<()> {
    if manifest.format != 2 || manifest.component != "agent" || manifest.target != target {
        return Err(invalid(
            "installed Agent manifest has an unexpected identity",
        ));
    }
    semver::Version::parse(&manifest.version)
        .map_err(|_| invalid("installed Agent version is not semantic"))?;
    validate_directory(bin)?;
    let expected_files = package_files(target);
    let mut expected = expected_files.iter().cloned().collect::<BTreeSet<_>>();
    expected.insert(PACKAGE_MANIFEST.into());
    expected.insert(ARCHIVE_DIGEST.into());
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
    if actual != expected || file_identities(bin, &expected_files)? != manifest.files {
        return Err(invalid(
            "installed Agent files differ from the release manifest",
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
