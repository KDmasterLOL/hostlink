//! Minimal ZIP package preflight shared by the updater and fresh enrollment.
//! The independently pinned archive SHA-256 is verified by the caller;
//! extracted file identities are verified before any bundle is published.

use super::super::{
    MAX_ARCHIVE_BYTES, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES, PACKAGE_MANIFEST,
    invalid, invalid_owned,
    manifest::{PackageManifest, package_files},
};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    path::Path,
};
use zip::ZipArchive;

pub(in crate::update) fn validate_contents(
    archive_path: &Path,
    target: &str,
    version: &str,
) -> io::Result<(PackageManifest, Vec<u8>)> {
    let archive_metadata = fs::symlink_metadata(archive_path)?;
    if !archive_metadata.is_file()
        || archive_metadata.len() == 0
        || archive_metadata.len() > MAX_ARCHIVE_BYTES
    {
        return Err(invalid("Agent archive is not a bounded regular file"));
    }

    let mut archive = ZipArchive::new(File::open(archive_path)?)
        .map_err(|error| invalid_owned(format!("invalid Agent ZIP archive: {error}")))?;
    // Use the same ZIP reader as self_update: reject conflicting local headers,
    // overlapping entries and duplicate names, not irrelevant ZIP layout details.
    archive
        .validate_header_consistency()
        .map_err(|error| invalid_owned(format!("invalid Agent ZIP headers: {error}")))?;

    let expected_files = package_files(target);
    let expected = expected_files
        .iter()
        .cloned()
        .chain(std::iter::once(PACKAGE_MANIFEST.to_owned()))
        .collect::<BTreeSet<_>>();
    if archive.len() != expected.len() {
        return Err(invalid(
            "Agent ZIP does not contain the required file inventory",
        ));
    }

    let prefix = format!("hostlink-agent-{target}/");
    let mut total_size = 0_u64;
    let mut manifest_bytes = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| invalid_owned(format!("invalid Agent ZIP member: {error}")))?;
        let relative = std::str::from_utf8(entry.name_raw())
            .map_err(|_| invalid("Agent ZIP member name is not UTF-8"))?
            .strip_prefix(&prefix)
            .ok_or_else(|| invalid("Agent ZIP member has an unexpected package root"))?;
        if !expected.contains(relative)
            || !entry.is_file()
            || entry.enclosed_name().is_none()
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
        {
            return Err(invalid("Agent ZIP contains an unexpected or unsafe member"));
        }

        let size = entry.size();
        if size > MAX_ENTRY_BYTES {
            return Err(invalid("Agent ZIP member exceeds its size limit"));
        }
        total_size = total_size
            .checked_add(size)
            .ok_or_else(|| invalid("Agent ZIP size overflow"))?;
        if total_size > MAX_TOTAL_BYTES {
            return Err(invalid(
                "Agent ZIP exceeds its total uncompressed size limit",
            ));
        }

        if relative == PACKAGE_MANIFEST {
            if size > MAX_MANIFEST_BYTES {
                return Err(invalid("Agent ZIP manifest exceeds its size limit"));
            }
            let mut bytes = Vec::new();
            (&mut entry)
                .take(MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != size {
                return Err(invalid("Agent ZIP manifest differs from its declared size"));
            }
            manifest_bytes = Some(bytes);
        }
    }
    let bytes = manifest_bytes.ok_or_else(|| invalid("Agent ZIP manifest is missing"))?;
    let manifest: PackageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_owned(format!("invalid Agent package manifest: {error}")))?;
    if manifest.format != 1
        || manifest.component != "agent"
        || manifest.target != target
        || manifest.version != version
        || manifest.files.keys().cloned().collect::<BTreeSet<_>>()
            != expected_files.into_iter().collect()
    {
        return Err(invalid(
            "Agent package manifest differs from the requested package",
        ));
    }
    Ok((manifest, bytes))
}
