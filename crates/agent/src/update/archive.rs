//! Archive path validation, strict ZIP index validation, and private package staging.

#[cfg(not(windows))]
use super::private_fs::{create_private_directory, validate_private_directory};
#[cfg(windows)]
use super::windows::{create_private_directory, validate_windows_private_acl};
use super::{
    MAX_ARCHIVE_BYTES, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES, PACKAGE_MANIFEST,
    invalid, invalid_owned,
    manifest::{FileIdentity, PackageManifest, package_files},
    private_fs::{hash_file, set_private_directory, set_staged_file_permissions},
    private_fs::{is_reparse_point, validate_path_has_no_reparse_components},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
use zip::ZipArchive;

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_LOCAL_SIGNATURE: u32 = 0x0403_4b50;

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
    let mut current = PathBuf::new();
    for component in archive.components() {
        current.push(component.as_os_str());
        if current == canonical_root {
            continue;
        }
        if current.starts_with(&canonical_root) {
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Err(invalid(
                    "Agent archive path contains a link or reparse point",
                ));
            }
        }
    }
    let canonical_archive = fs::canonicalize(archive)?;
    if !canonical_archive.starts_with(&canonical_root) {
        return Err(invalid("Agent archive must be beneath the install root"));
    }
    let metadata = fs::symlink_metadata(archive)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid("Agent archive is not a regular file"));
    }
    validate_path_has_no_reparse_components(archive)?;
    #[cfg(windows)]
    validate_windows_private_acl(&canonical_archive, &metadata)?;
    Ok(canonical_archive)
}

pub(super) fn validate_and_stage_archive(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    staging_parent: &Path,
) -> io::Result<(PackageManifest, tempfile::TempDir)> {
    let stage = tempfile::Builder::new()
        .prefix(".agent-package-")
        .tempdir_in(staging_parent)?;
    set_private_directory(stage.path())?;
    let staged_archive = stage.path().join("package.zip");
    let mut source = File::open(archive_path)?;
    let source_size = source.metadata()?.len();
    if source_size == 0 || source_size > MAX_ARCHIVE_BYTES {
        return Err(invalid(
            "Agent package archive exceeds its compressed size limit",
        ));
    }
    let mut archive_copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_archive)?;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or_else(|| invalid("Agent archive size overflow"))?;
        if copied > MAX_ARCHIVE_BYTES {
            return Err(invalid(
                "Agent package archive exceeds its compressed size limit",
            ));
        }
        archive_copy.write_all(&buffer[..count])?;
    }
    if copied == 0 {
        return Err(invalid("Agent package archive is empty"));
    }
    archive_copy.sync_all()?;
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
    validate_central_directory(&mut File::open(&staged_archive)?, copied, &expected_names)?;
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
    self_update::Extract::from_source(&staged_archive)
        .archive(self_update::ArchiveKind::Zip)
        .extract_into(&extraction_root)
        .map_err(|error| invalid_owned(format!("Agent ZIP extraction failed: {error}")))?;
    let package_root = extraction_root.join(format!("hostlink-agent-{target}"));
    let package_metadata = fs::symlink_metadata(&package_root)?;
    if !package_metadata.is_dir() || is_reparse_point(&package_metadata) {
        return Err(invalid(
            "Agent ZIP extraction produced an unsafe package root",
        ));
    }
    set_private_directory(&package_root)?;
    let package_metadata = fs::symlink_metadata(&package_root)?;
    #[cfg(windows)]
    validate_windows_private_acl(&package_root, &package_metadata)?;
    #[cfg(not(windows))]
    validate_private_directory(&package_root, &package_metadata)?;
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

/// Validate the small, single-disk, non-ZIP64 package index before `ZipArchive` can
/// normalize duplicate central-directory names into its filename-keyed map.
fn validate_central_directory(
    archive: &mut File,
    archive_size: u64,
    expected_names: &[String],
) -> io::Result<()> {
    const EOCD_SIZE: u64 = 22;
    const CENTRAL_HEADER_SIZE: u64 = 46;
    if archive_size < EOCD_SIZE || expected_names.len() > usize::from(u16::MAX) {
        return Err(invalid(
            "Agent ZIP has an unsupported archive size or member count",
        ));
    }

    let mut signature = [0_u8; 4];
    archive.seek(SeekFrom::Start(0))?;
    archive.read_exact(&mut signature)?;
    if read_u32(&signature) != ZIP_LOCAL_SIGNATURE {
        return Err(invalid(
            "Agent ZIP has an unsupported prefix or local header",
        ));
    }

    let eocd_offset = archive_size
        .checked_sub(EOCD_SIZE)
        .ok_or_else(|| invalid("Agent ZIP end record is missing"))?;
    archive.seek(SeekFrom::Start(eocd_offset))?;
    let mut eocd = [0_u8; 22];
    archive.read_exact(&mut eocd)?;
    if read_u32(&eocd[0..4]) != ZIP_EOCD_SIGNATURE
        || read_u16(&eocd[4..6]) != 0
        || read_u16(&eocd[6..8]) != 0
        || usize::from(read_u16(&eocd[8..10])) != expected_names.len()
        || usize::from(read_u16(&eocd[10..12])) != expected_names.len()
        || read_u16(&eocd[20..22]) != 0
    {
        return Err(invalid(
            "Agent ZIP end record is non-canonical or has an unexpected member count",
        ));
    }
    let central_size = u64::from(read_u32(&eocd[12..16]));
    let central_offset = u64::from(read_u32(&eocd[16..20]));
    if central_size == u64::from(u32::MAX)
        || central_offset == u64::from(u32::MAX)
        || central_offset
            .checked_add(central_size)
            .filter(|end| *end == eocd_offset)
            .is_none()
    {
        return Err(invalid(
            "Agent ZIP central directory bounds are unsupported or inconsistent",
        ));
    }

    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| invalid("Agent ZIP central directory size overflow"))?;
    let mut cursor = central_offset;
    let mut previous_local_offset = None;
    for expected_name in expected_names {
        let header_end = cursor
            .checked_add(CENTRAL_HEADER_SIZE)
            .filter(|end| *end <= central_end)
            .ok_or_else(|| invalid("Agent ZIP central directory is truncated"))?;
        archive.seek(SeekFrom::Start(cursor))?;
        let mut header = [0_u8; 46];
        archive.read_exact(&mut header)?;
        if read_u32(&header[0..4]) != ZIP_CENTRAL_SIGNATURE {
            return Err(invalid("Agent ZIP central directory has an invalid record"));
        }
        let compressed_size = read_u32(&header[20..24]);
        let uncompressed_size = read_u32(&header[24..28]);
        let name_size = u64::from(read_u16(&header[28..30]));
        let extra_size = u64::from(read_u16(&header[30..32]));
        let comment_size = u64::from(read_u16(&header[32..34]));
        let disk_start = read_u16(&header[34..36]);
        let local_offset = u64::from(read_u32(&header[42..46]));
        let variable_end = header_end
            .checked_add(name_size)
            .and_then(|end| end.checked_add(extra_size))
            .and_then(|end| end.checked_add(comment_size))
            .filter(|end| *end <= central_end)
            .ok_or_else(|| invalid("Agent ZIP central record fields exceed directory bounds"))?;
        if name_size == 0
            || disk_start != 0
            || compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_offset == u64::from(u32::MAX)
            || previous_local_offset.is_some_and(|previous| local_offset <= previous)
        {
            return Err(invalid("Agent ZIP uses an unsupported central record"));
        }
        let name_len = usize::try_from(name_size)
            .map_err(|_| invalid("Agent ZIP member name size is unsupported"))?;
        let mut name = vec![0_u8; name_len];
        archive.read_exact(&mut name)?;
        if name.as_slice() != expected_name.as_bytes() {
            return Err(invalid(
                "Agent ZIP central member names or order do not match the package contract",
            ));
        }
        let extra_len = usize::try_from(extra_size)
            .map_err(|_| invalid("Agent ZIP extra field size is unsupported"))?;
        let mut extra = vec![0_u8; extra_len];
        archive.read_exact(&mut extra)?;
        validate_non_zip64_extra_fields(&extra)?;

        let local_fixed_end = local_offset
            .checked_add(30)
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP local header offset is invalid"))?;
        archive.seek(SeekFrom::Start(local_offset))?;
        let mut local_header = [0_u8; 30];
        archive.read_exact(&mut local_header)?;
        if read_u32(&local_header[0..4]) != ZIP_LOCAL_SIGNATURE
            || (previous_local_offset.is_none() && local_offset != 0)
        {
            return Err(invalid(
                "Agent ZIP contains a prefix or invalid local header",
            ));
        }
        let local_name_size = usize::from(read_u16(&local_header[26..28]));
        let local_extra_size = usize::from(read_u16(&local_header[28..30]));
        let local_fields_size = local_name_size
            .checked_add(local_extra_size)
            .ok_or_else(|| invalid("Agent ZIP local header field size overflow"))?;
        let local_variable_end = local_fixed_end
            .checked_add(
                u64::try_from(local_fields_size)
                    .map_err(|_| invalid("Agent ZIP local header field size is unsupported"))?,
            )
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP local header fields exceed archive bounds"))?;
        if read_u32(&local_header[18..22]) == u32::MAX
            || read_u32(&local_header[22..26]) == u32::MAX
            || local_name_size != name_len
        {
            return Err(invalid("Agent ZIP local header uses unsupported fields"));
        }
        let mut local_name = vec![0_u8; local_name_size];
        archive.read_exact(&mut local_name)?;
        if local_name != name {
            return Err(invalid("Agent ZIP local and central names do not match"));
        }
        let mut local_extra = vec![0_u8; local_extra_size];
        archive.read_exact(&mut local_extra)?;
        validate_non_zip64_extra_fields(&local_extra)?;
        local_variable_end
            .checked_add(u64::from(compressed_size))
            .filter(|end| *end <= central_offset)
            .ok_or_else(|| invalid("Agent ZIP member data exceeds archive bounds"))?;
        previous_local_offset = Some(local_offset);
        cursor = variable_end;
    }
    if cursor != central_end {
        return Err(invalid(
            "Agent ZIP central directory contains hidden or trailing records",
        ));
    }
    Ok(())
}

fn validate_non_zip64_extra_fields(mut fields: &[u8]) -> io::Result<()> {
    while !fields.is_empty() {
        if fields.len() < 4 {
            return Err(invalid("Agent ZIP extra field is truncated"));
        }
        let field_id = read_u16(&fields[0..2]);
        let field_size = usize::from(read_u16(&fields[2..4]));
        fields = &fields[4..];
        if field_id == 0x0001 || field_size > fields.len() {
            return Err(invalid("Agent ZIP has a ZIP64 or malformed extra field"));
        }
        fields = &fields[field_size..];
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
