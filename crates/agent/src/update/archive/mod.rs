//! Archive path validation, strict ZIP index validation, and private package staging.

use super::private_fs::create_private_directory;
use super::staging::PrivateTempDir;
use super::{
    MAX_ARCHIVE_BYTES, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES, PACKAGE_MANIFEST,
    invalid, invalid_owned,
    manifest::{FileIdentity, PackageManifest, package_files},
    private_fs::{hash_file, set_staged_file_permissions},
    private_fs::{is_reparse_point, validate_path_has_no_reparse_components},
};
use private_fs::PrivateDir;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};
use zip::ZipArchive;

mod zip_index;

pub(super) fn validate_archive_path(root: &Path, archive: &Path) -> io::Result<PathBuf> {
    if !archive.is_absolute()
        || archive
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid(
            "Agent archive path must be absolute and contain no parent traversal",
        ));
    }
    let canonical_root = fs::canonicalize(root)?;
    // Exact-component no-reparse checking is performed below, after
    // establishing that the canonical archive belongs to this install root.
    let canonical_archive = fs::canonicalize(archive)?;
    if !canonical_archive.starts_with(&canonical_root) {
        return Err(invalid("Agent archive must be beneath the install root"));
    }
    let metadata = fs::symlink_metadata(archive)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid("Agent archive is not a regular file"));
    }
    validate_path_has_no_reparse_components(archive)?;
    Ok(canonical_archive)
}

pub(super) fn validate_and_stage_archive(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    staging_parent: &Path,
) -> io::Result<(PackageManifest, PrivateTempDir)> {
    let stage = PrivateTempDir::new_in(staging_parent, ".agent-package-")?;
    let stage_dir = PrivateDir::open(stage.path()).map_err(io::Error::other)?;
    let staged_archive = stage.path().join("package.zip");
    let mut source = File::open(archive_path)?;
    let source_size = source.metadata()?.len();
    if source_size == 0 || source_size > MAX_ARCHIVE_BYTES {
        return Err(invalid(
            "Agent package archive exceeds its compressed size limit",
        ));
    }
    let mut archive_copy = stage_dir.create("package.zip").map_err(io::Error::other)?;
    // Enforce the bound before writing a byte beyond it, even if the source
    // grows after its initial metadata check.
    let copied = io::copy(
        &mut (&mut source).take(MAX_ARCHIVE_BYTES),
        &mut archive_copy,
    )?;
    if copied == 0 {
        return Err(invalid("Agent package archive is empty"));
    }
    if copied == MAX_ARCHIVE_BYTES && source.read(&mut [0_u8; 1])? != 0 {
        return Err(invalid(
            "Agent package archive exceeds its compressed size limit",
        ));
    }
    archive_copy.sync_all().map_err(io::Error::other)?;
    drop(archive_copy);
    if hash_file(&staged_archive, MAX_ARCHIVE_BYTES)? != archive_sha256 {
        return Err(invalid("selected Agent archive SHA-256 does not match"));
    }
    let prefix = format!("hostlink-agent-{target}/");
    let expected_order = package_files(target)
        .into_iter()
        .chain(std::iter::once(PACKAGE_MANIFEST.to_owned()))
        .collect::<Vec<_>>();
    let expected_names = expected_order
        .iter()
        .map(|name| format!("{prefix}{name}"))
        .collect::<Vec<_>>();
    zip_index::validate_central_directory(
        &mut File::open(&staged_archive)?,
        copied,
        &expected_names,
    )?;
    let mut archive = ZipArchive::new(File::open(&staged_archive)?)
        .map_err(|error| invalid_owned(format!("invalid Agent ZIP archive: {error}")))?;
    let expected = expected_order.iter().cloned().collect::<BTreeSet<_>>();
    if archive.len() != expected.len() {
        return Err(invalid(
            "Agent archive member inventory does not match the package contract",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut identities = BTreeMap::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut manifest_bytes = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| invalid_owned(format!("invalid Agent ZIP member: {error}")))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| invalid("Agent ZIP entry name is not UTF-8"))?
            .to_owned();
        let relative = name
            .strip_prefix(&prefix)
            .ok_or_else(|| invalid("Agent ZIP entry has an unexpected package root"))?;
        if relative.contains('/')
            || relative.contains('\\')
            || relative.is_empty()
            || expected_order.get(index).map(String::as_str) != Some(relative)
            || !expected.contains(relative)
            || !entry.is_file()
            || entry.enclosed_name().is_none()
            || !seen.insert(relative.to_owned())
        {
            return Err(invalid("Agent ZIP contains an unsafe or unexpected entry"));
        }
        if entry.is_symlink()
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
        {
            return Err(invalid(
                "Agent ZIP contains a symlink or non-regular member",
            ));
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(invalid("Agent ZIP uses an unsupported compression method"));
        }
        let declared = entry.size();
        if declared > MAX_ENTRY_BYTES || entry.compressed_size() > MAX_ARCHIVE_BYTES {
            return Err(invalid("Agent ZIP member exceeds its size limit"));
        }
        total = total
            .checked_add(declared)
            .ok_or_else(|| invalid("Agent ZIP size overflow"))?;
        if total > MAX_TOTAL_BYTES {
            return Err(invalid(
                "Agent ZIP exceeds its total uncompressed size limit",
            ));
        }
        let mut hasher = Sha256::new();
        let mut written = 0_u64;
        let mut manifest_capture = (relative == PACKAGE_MANIFEST).then(Vec::new);
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            written = written
                .checked_add(count as u64)
                .ok_or_else(|| invalid("Agent ZIP size overflow"))?;
            if written > declared || written > MAX_ENTRY_BYTES {
                return Err(invalid("Agent ZIP member exceeds its declared size"));
            }
            hasher.update(&buffer[..count]);
            if let Some(capture) = &mut manifest_capture {
                if written > MAX_MANIFEST_BYTES {
                    return Err(invalid("Agent package manifest exceeds its size limit"));
                }
                capture.extend_from_slice(&buffer[..count]);
            }
        }
        if written != declared {
            return Err(invalid(
                "Agent ZIP member size does not match its declaration",
            ));
        }
        if relative == PACKAGE_MANIFEST {
            manifest_bytes = manifest_capture;
        } else {
            identities.insert(
                relative.to_owned(),
                FileIdentity {
                    size: written,
                    sha256: format!("{:x}", hasher.finalize()),
                },
            );
        }
    }
    if seen != expected {
        return Err(invalid("Agent archive is missing required package files"));
    }
    let bytes = manifest_bytes.ok_or_else(|| invalid("Agent package manifest is missing"))?;
    let manifest: PackageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_owned(format!("invalid Agent package manifest: {error}")))?;
    if manifest.format != 1
        || manifest.component != "agent"
        || manifest.target != target
        || manifest.version != version
    {
        return Err(invalid(
            "Agent package manifest does not match the selected version and target",
        ));
    }
    if manifest.files != identities
        || manifest.files.keys().cloned().collect::<BTreeSet<_>>()
            != package_files(target).into_iter().collect()
    {
        return Err(invalid(
            "Agent package manifest file identities do not match the archive",
        ));
    }

    // The raw central directory, complete member inventory, bounded expanded sizes, member
    // types, and content digests are validated above before the library is allowed to extract.
    // Extraction is confined to this private directory; its output is independently checked
    // against those exact identities before publication.
    let extraction_root = stage.path().join("extracted");
    create_private_directory(&extraction_root)?;
    let package_root = extraction_root.join(format!("hostlink-agent-{target}"));
    create_private_directory(&package_root)?;
    let package_dir = PrivateDir::open(&package_root).map_err(io::Error::other)?;
    // self_update truncates these exact precreated files. It must not create Windows
    // files/directories with inherited ACLs and then repair them after exposure.
    for name in &expected_order {
        package_dir.create(name).map_err(io::Error::other)?;
    }
    self_update::Extract::from_source(&staged_archive)
        .archive(self_update::ArchiveKind::Zip)
        .extract_into(&extraction_root)
        .map_err(|error| invalid_owned(format!("Agent ZIP extraction failed: {error}")))?;
    let package_metadata = fs::symlink_metadata(&package_root)?;
    if !package_metadata.is_dir() || is_reparse_point(&package_metadata) {
        return Err(invalid(
            "Agent ZIP extraction produced an unsafe package root",
        ));
    }
    PrivateDir::open(&package_root).map_err(io::Error::other)?;
    let actual_names = fs::read_dir(&package_root)?
        .map(|entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || is_reparse_point(&metadata) {
                return Err(invalid("Agent ZIP extraction produced a non-regular file"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Agent ZIP extraction produced a non-UTF-8 file name"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    if actual_names != expected {
        return Err(invalid(
            "Agent ZIP extraction inventory differs from its validated index",
        ));
    }
    for (name, identity) in &manifest.files {
        let path = package_root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.len() != identity.size || hash_file(&path, MAX_ENTRY_BYTES)? != identity.sha256
        {
            return Err(invalid(
                "Agent ZIP extracted file differs from its verified digest",
            ));
        }
        set_staged_file_permissions(&path, name)?;
    }
    let extracted_manifest = fs::read(package_root.join(PACKAGE_MANIFEST))?;
    if extracted_manifest != bytes {
        return Err(invalid(
            "Agent ZIP extracted manifest differs from its verified bytes",
        ));
    }
    set_staged_file_permissions(&package_root.join(PACKAGE_MANIFEST), PACKAGE_MANIFEST)?;
    Ok((manifest, stage))
}
