//! Archive path validation, strict ZIP index validation, and private package staging.

use super::private_fs::create_private_directory;
use super::staging::PrivateTempDir;
use super::{
    MAX_ARCHIVE_BYTES, MAX_ENTRY_BYTES, PACKAGE_MANIFEST, invalid, invalid_owned,
    manifest::{PackageManifest, package_files},
    private_fs::is_reparse_point,
    private_fs::{hash_file, set_staged_file_permissions},
};
use private_fs::PrivateDir;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

mod contents;
mod zip_index;

pub(super) use contents::validate_contents;

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
    let (manifest, bytes) = validate_contents(&staged_archive, target, version)?;
    let expected_order = package_files(target)
        .into_iter()
        .chain(std::iter::once(PACKAGE_MANIFEST.to_owned()))
        .collect::<Vec<_>>();
    let expected = expected_order.iter().cloned().collect::<BTreeSet<_>>();

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
