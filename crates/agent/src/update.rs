//! Exact, local, Agent-only package updates.
//!
//! Updates are serialized with an OS file lock, staged under the user-owned install root,
//! and published only after the selected archive, target, version, and file manifest agree.
//! Windows publication is deliberately refused until the stopped-process launcher handoff is
//! integrated; replacing a running Windows executable is never attempted here.

use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::{collections::btree_map::Entry, fmt};
use zip::ZipArchive;

const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const PACKAGE_MANIFEST: &str = "manifest.json";
const INSTALL_METADATA: &str = "install.json";
const EXECUTABLE_BASE: &str = "hostlink-agent";
const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_LOCAL_SIGNATURE: u32 = 0x0403_4b50;

/// One exact, externally selected Agent package. `archive_file` must be beneath `install_root`.
#[derive(Clone, Debug)]
pub struct AgentUpdateRequest {
    pub install_root: PathBuf,
    pub archive_file: PathBuf,
    pub archive_sha256: String,
    pub target: String,
    pub version: String,
}

/// The updater's externally visible result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentUpdateOutcome {
    AlreadyCurrent {
        version: String,
        archive_sha256: String,
    },
    DeferredActiveJobs {
        job_ids: Vec<String>,
    },
    Installed {
        version: String,
        archive_sha256: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageManifest {
    format: u32,
    component: String,
    target: String,
    version: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    files: BTreeMap<String, FileIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallMetadata {
    format: u32,
    target: String,
    installed_version: String,
    installed_package_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    installed_files: BTreeMap<String, FileIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapReceipt {
    format: u32,
    component: String,
    target: String,
    version: String,
    archive_sha256: String,
    sidecar_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    files: BTreeMap<String, FileIdentity>,
}

fn deserialize_unique_file_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, FileIdentity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueFileMapVisitor;

    impl<'de> Visitor<'de> for UniqueFileMapVisitor {
        type Value = BTreeMap<String, FileIdentity>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of unique Agent package file identities")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut files = BTreeMap::new();
            while let Some((name, identity)) = map.next_entry::<String, FileIdentity>()? {
                match files.entry(name) {
                    Entry::Vacant(entry) => {
                        entry.insert(identity);
                    }
                    Entry::Occupied(_) => {
                        return Err(de::Error::custom("duplicate Agent package manifest file"));
                    }
                }
            }
            Ok(files)
        }
    }

    deserializer.deserialize_map(UniqueFileMapVisitor)
}

#[cfg(not(windows))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationJournal {
    format: u32,
    backup: String,
    old_metadata: InstallMetadata,
}

/// Validate and apply one exact Agent archive.
///
/// The durable-job store beneath `install_root` is read under the same update lock. Any returned
/// job ID defers the update; corrupt or unreadable job state is propagated as an error by
/// `jobs::active_ids`.
pub fn apply(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    validate_request(request)?;
    validate_user_owned_root(&request.install_root)?;
    let archive_path = validate_archive_path(&request.install_root, &request.archive_file)?;
    let _update_lock = crate::jobs::acquire_update_lock(&request.install_root)?;

    let jobs_root = request.install_root.join("jobs");
    let active_ids = crate::jobs::active_ids(&jobs_root)?;
    if !active_ids.is_empty() {
        return Ok(AgentUpdateOutcome::DeferredActiveJobs {
            job_ids: active_ids,
        });
    }
    #[cfg(not(windows))]
    recover_interrupted_publication(&request.install_root)?;

    let (manifest, staged_files) = validate_and_stage_archive(
        &archive_path,
        &request.archive_sha256,
        &request.target,
        &request.version,
        &request.install_root,
    )?;
    let bin_root = request.install_root.join("bin");
    let metadata_path = request.install_root.join(INSTALL_METADATA);
    let old_metadata = read_install_metadata(&metadata_path)?;
    validate_installed(&bin_root, &old_metadata, &request.target)?;

    if old_metadata.installed_package_sha256 == request.archive_sha256 {
        if old_metadata.installed_version != request.version {
            return Err(invalid(
                "installed version conflicts with the selected archive SHA-256",
            ));
        }
        drop(staged_files);
        return Ok(AgentUpdateOutcome::AlreadyCurrent {
            version: request.version.clone(),
            archive_sha256: request.archive_sha256.clone(),
        });
    }

    #[cfg(windows)]
    {
        let _ = (manifest, staged_files);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Agent update requires the stopped-runtime launcher handoff",
        ))
    }

    #[cfg(not(windows))]
    {
        publish_linux(
            &request.install_root,
            &bin_root,
            &metadata_path,
            request,
            manifest,
            old_metadata,
            staged_files,
        )?;
        Ok(AgentUpdateOutcome::Installed {
            version: request.version.clone(),
            archive_sha256: request.archive_sha256.clone(),
        })
    }
}

fn validate_request(request: &AgentUpdateRequest) -> io::Result<()> {
    if request.install_root.as_os_str().is_empty() || !request.install_root.is_absolute() {
        return Err(invalid("Agent install root must be an absolute path"));
    }
    validate_sha256(&request.archive_sha256)?;
    semver::Version::parse(&request.version)
        .map_err(|_| invalid("Agent package version must be exact semantic version"))?;
    if !supported_targets().contains(&request.target.as_str()) {
        return Err(invalid("unsupported Agent target triple"));
    }
    if !target_matches_runtime(&request.target) {
        return Err(invalid("Agent package target does not match this runtime"));
    }
    Ok(())
}

fn validate_sha256(digest: &str) -> io::Result<()> {
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "SHA-256 must contain 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn supported_targets() -> &'static [&'static str] {
    &[
        "x86_64-pc-windows-msvc",
        "x86_64-win7-windows-msvc",
        "i686-win7-windows-msvc",
        "x86_64-unknown-linux-gnu",
    ]
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn target_matches_runtime(target: &str) -> bool {
    target == "x86_64-unknown-linux-gnu"
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn target_matches_runtime(target: &str) -> bool {
    matches!(
        target,
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc"
    )
}

#[cfg(all(target_os = "windows", target_arch = "x86"))]
fn target_matches_runtime(target: &str) -> bool {
    target == "i686-win7-windows-msvc"
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86")
)))]
fn target_matches_runtime(_target: &str) -> bool {
    false
}

fn validate_user_owned_root(root: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid("Agent install root is not a real directory"));
    }
    if fs::canonicalize(root)? != root {
        return Err(invalid("Agent install root must not use a symlinked path"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and reads only the current process identity.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid("Agent install root is not owned by this user"));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(invalid("Agent install root permissions are not private"));
        }
    }
    #[cfg(windows)]
    {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| invalid("LOCALAPPDATA is required for user-scoped Agent updates"))?;
        let expected = Path::new(&local_app_data).join("HostLink").join("Agent");
        if fs::canonicalize(root)? != fs::canonicalize(expected)? {
            return Err(invalid(
                "Agent install root is outside this user's HostLink directory",
            ));
        }
        validate_windows_private_acl(root, &metadata)?;
    }
    Ok(())
}

fn validate_archive_path(root: &Path, archive: &Path) -> io::Result<PathBuf> {
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

fn validate_and_stage_archive(
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
        let destination = stage.path().join(relative);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        set_staged_file_permissions(&destination, relative)?;
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
            output.write_all(&buffer[..count])?;
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
        output.sync_all()?;
        set_staged_file_permissions(&destination, relative)?;
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

/// Verify an exact package for a fresh install and publish its verified members into a new,
/// caller-owned private directory. The running sidecar must be the exact executable in the ZIP.
///
/// # Errors
///
/// Returns an error for invalid source digest, target, version, archive inventory, permissions,
/// manifest identities, sidecar mismatch, unsafe output parent, or any failed file operation.
pub fn verify_fresh_package(
    archive_path: &Path,
    archive_sha256: &str,
    target: &str,
    version: &str,
    output: &Path,
) -> io::Result<()> {
    validate_sha256(archive_sha256)?;
    semver::Version::parse(version)
        .map_err(|_| invalid("Agent package version must be exact semantic version"))?;
    if version != env!("CARGO_PKG_VERSION") {
        return Err(invalid(
            "verifier sidecar version does not match selected package version",
        ));
    }
    if !supported_targets().contains(&target) || !target_matches_runtime(target) {
        return Err(invalid("Agent package target does not match this runtime"));
    }
    let metadata = fs::symlink_metadata(archive_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid("Agent archive is not a regular file"));
    }
    validate_path_has_no_reparse_components(archive_path)?;
    let parent = output
        .parent()
        .ok_or_else(|| invalid("package output must have a parent directory"))?;
    validate_fresh_output_parent(parent)?;
    if output.exists() || fs::symlink_metadata(output).is_ok() {
        return Err(invalid("package output already exists"));
    }
    let canonical_archive = fs::canonicalize(archive_path)?;
    let (manifest, staged) =
        validate_and_stage_archive(&canonical_archive, archive_sha256, target, version, parent)?;
    let executable = package_files(target)
        .into_iter()
        .find(|name| name == "hostlink-agent" || name == "hostlink-agent.exe")
        .ok_or_else(|| invalid("Agent executable is missing from package contract"))?;
    let running = std::env::current_exe()?;
    let expected_executable = manifest
        .files
        .get(&executable)
        .ok_or_else(|| invalid("Agent executable identity is missing from manifest"))?;
    if hash_file(&running, MAX_ENTRY_BYTES)? != expected_executable.sha256 {
        return Err(invalid(
            "verifier sidecar does not match the package Agent executable",
        ));
    }
    let install_metadata = InstallMetadata {
        format: 1,
        target: target.to_owned(),
        installed_version: version.to_owned(),
        installed_package_sha256: archive_sha256.to_owned(),
        installed_files: manifest.files.clone(),
    };
    let metadata_path = staged.path().join(INSTALL_METADATA);
    let mut metadata_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&metadata_path)?;
    metadata_file
        .write_all(&serde_json::to_vec_pretty(&install_metadata).map_err(io::Error::other)?)?;
    metadata_file.sync_all()?;
    set_staged_file_permissions(&metadata_path, INSTALL_METADATA)?;
    let receipt_path = staged.path().join("bootstrap-receipt.json");
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)?;
    receipt_file.write_all(
        &serde_json::to_vec_pretty(&serde_json::json!({
            "format": 1,
            "component": manifest.component,
            "target": manifest.target,
            "version": manifest.version,
            "archive_sha256": archive_sha256,
            "sidecar_sha256": expected_executable.sha256,
            "files": manifest.files,
        }))
        .map_err(io::Error::other)?,
    )?;
    receipt_file.sync_all()?;
    set_staged_file_permissions(&receipt_path, "bootstrap-receipt.json")?;
    // Windows refuses renaming a directory containing still-open file handles
    // (ERROR_ACCESS_DENIED), even after each file's sync_all has succeeded.
    // Publish only after closing both verified metadata and receipt files.
    drop(receipt_file);
    drop(metadata_file);
    // Windows std::fs::File::open cannot open a directory for sync_all.
    // The member files and receipt have already been individually flushed;
    // the directory durability barrier is available on Unix only.
    #[cfg(not(windows))]
    sync_directory(staged.path())?;
    fs::rename(staged.path(), output)?;
    #[cfg(not(windows))]
    sync_directory(parent)?;
    println!(
        "Verified Agent package: target={target} version={version} archive_sha256={archive_sha256}"
    );
    Ok(())
}

/// Complete a fresh bootstrap only after the ZIP's extracted binaries and receipt are installed.
///
/// # Errors
///
/// Returns an error unless the install root, enrollment state, installed package, source receipt,
/// and pending marker all validate. On error the pending marker remains for reconciliation.
pub fn finalize_fresh_install(root: &Path) -> io::Result<()> {
    validate_user_owned_root(root)?;
    let pending = root.join("enrollment.pending");
    let pending_file = open_private_file(&pending, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(&pending, &pending_file.metadata()?)?;
    drop(pending_file);

    let state = root.join("state");
    let state_metadata = fs::symlink_metadata(&state)?;
    if !state_metadata.is_dir()
        || state_metadata.file_type().is_symlink()
        || is_reparse_point(&state_metadata)
    {
        return Err(invalid("fresh Agent state directory is missing or unsafe"));
    }
    #[cfg(not(windows))]
    validate_private_directory(&state, &state_metadata)?;
    #[cfg(windows)]
    validate_windows_private_acl(&state, &state_metadata)?;
    let config = state.join("agent.json");
    let config_metadata = fs::symlink_metadata(&config)?;
    if !config_metadata.is_file()
        || config_metadata.file_type().is_symlink()
        || is_reparse_point(&config_metadata)
    {
        return Err(invalid("fresh Agent configuration is missing or unsafe"));
    }
    #[cfg(windows)]
    validate_windows_private_acl(&config, &config_metadata)?;

    let metadata_path = root.join(INSTALL_METADATA);
    let installed = read_install_metadata(&metadata_path)?;
    if !supported_targets().contains(&installed.target.as_str())
        || !target_matches_runtime(&installed.target)
        || installed.installed_version != env!("CARGO_PKG_VERSION")
    {
        return Err(invalid(
            "fresh installed package target or version does not match this Agent",
        ));
    }
    validate_installed(&root.join("bin"), &installed, &installed.target)?;
    let receipt_path = root.join("bootstrap-receipt.json");
    let receipt_file = open_private_file(&receipt_path, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(&receipt_path, &receipt_file.metadata()?)?;
    let mut receipt_bytes = Vec::new();
    receipt_file
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut receipt_bytes)?;
    if receipt_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("bootstrap receipt exceeds its size limit"));
    }
    let receipt: BootstrapReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| invalid_owned(format!("invalid bootstrap receipt: {error}")))?;
    let executable = package_files(&installed.target)
        .into_iter()
        .find(|name| name == "hostlink-agent" || name == "hostlink-agent.exe")
        .ok_or_else(|| invalid("Agent executable is missing from package contract"))?;
    if receipt.format != 1
        || receipt.component != "agent"
        || receipt.target != installed.target
        || receipt.version != installed.installed_version
        || receipt.archive_sha256 != installed.installed_package_sha256
        || receipt.files != installed.installed_files
    {
        return Err(invalid(
            "bootstrap receipt does not match installed package metadata",
        ));
    }
    let executable_identity = receipt
        .files
        .get(&executable)
        .ok_or_else(|| invalid("bootstrap receipt omits the Agent executable"))?;
    if receipt.sidecar_sha256 != executable_identity.sha256 {
        return Err(invalid(
            "bootstrap receipt sidecar identity does not match the package",
        ));
    }
    fs::remove_file(&pending)?;
    #[cfg(not(windows))]
    sync_directory(root)?;
    Ok(())
}

fn validate_fresh_output_parent(path: &Path) -> io::Result<()> {
    validate_path_has_no_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid(
            "package output parent is not a real private directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and reads only the current process identity.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                "package output parent is not private and user-owned",
            ));
        }
    }
    #[cfg(windows)]
    validate_windows_private_acl(path, &metadata)?;
    Ok(())
}

fn validate_path_has_no_reparse_components(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid(
            "bootstrap path must be absolute and contain no traversal",
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid(
                "bootstrap path contains a symlink or reparse point",
            ));
        }
    }
    Ok(())
}

fn package_files(target: &str) -> Vec<String> {
    let mut files = vec![
        if target.contains("windows") {
            "hostlink-agent.exe"
        } else {
            EXECUTABLE_BASE
        }
        .to_owned(),
    ];
    if target.contains("windows") {
        files.extend(
            [
                "Install-HostLink-Agent.ps1",
                "Run-HostLink-Agent.ps1",
                "Update-HostLink-Agent.ps1",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    files
}

fn read_install_metadata(path: &Path) -> io::Result<InstallMetadata> {
    let file = open_private_file(path, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(path, &file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid("Agent install metadata exceeds its size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_owned(format!("invalid Agent install metadata: {error}")))
}

fn validate_installed(bin_root: &Path, metadata: &InstallMetadata, target: &str) -> io::Result<()> {
    if metadata.format != 1 || metadata.target != target {
        return Err(invalid(
            "installed Agent metadata has a different format or target",
        ));
    }
    semver::Version::parse(&metadata.installed_version)
        .map_err(|_| invalid("installed Agent version metadata is malformed"))?;
    validate_sha256(&metadata.installed_package_sha256)
        .map_err(|_| invalid("installed Agent archive digest metadata is malformed"))?;
    let bin_metadata = fs::symlink_metadata(bin_root)?;
    if !bin_metadata.is_dir()
        || bin_metadata.file_type().is_symlink()
        || is_reparse_point(&bin_metadata)
    {
        return Err(invalid(
            "installed Agent bin directory is missing or unsafe",
        ));
    }
    #[cfg(windows)]
    validate_windows_private_acl(bin_root, &bin_metadata)?;
    semver::Version::parse(&metadata.installed_version)
        .map_err(|_| invalid("installed Agent version metadata is malformed"))?;
    validate_sha256(&metadata.installed_package_sha256)
        .map_err(|_| invalid("installed Agent archive digest metadata is malformed"))?;
    let bin_metadata = fs::symlink_metadata(bin_root)?;
    if !bin_metadata.is_dir()
        || bin_metadata.file_type().is_symlink()
        || is_reparse_point(&bin_metadata)
    {
        return Err(invalid(
            "installed Agent bin directory is missing or unsafe",
        ));
    }
    let expected = package_files(target).into_iter().collect::<BTreeSet<_>>();
    let mut actual_names = BTreeSet::new();
    for entry in fs::read_dir(bin_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("installed Agent filename is not valid UTF-8"))?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() || !actual_names.insert(name) {
            return Err(invalid(
                "installed Agent bin contains an unsafe or unexpected entry",
            ));
        }
        #[cfg(windows)]
        validate_windows_private_acl(&entry.path(), &entry.metadata()?)?;
    }
    if actual_names != expected {
        return Err(invalid(
            "installed Agent bin inventory differs from its exact package",
        ));
    }
    let actual = file_identities(bin_root, &package_files(target))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for name in package_files(target) {
            let mode = fs::metadata(bin_root.join(&name))?.mode();
            if mode & 0o022 != 0 || (name == EXECUTABLE_BASE && mode & 0o100 == 0) {
                return Err(invalid("installed Agent package permissions are unsafe"));
            }
        }
    }
    if actual != metadata.installed_files {
        return Err(invalid(
            "installed Agent files do not match their recorded integrity metadata",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
#[cfg(not(windows))]
fn publish_linux(
    root: &Path,
    bin_root: &Path,
    metadata_path: &Path,
    request: &AgentUpdateRequest,
    manifest: PackageManifest,
    old_metadata: InstallMetadata,
    staged: tempfile::TempDir,
) -> io::Result<()> {
    let updates = root.join(".updates");
    create_private_directory(&updates)?;
    let backup = updates.join(format!(
        "backup-{}-{}",
        old_metadata.installed_version, old_metadata.installed_package_sha256
    ));
    if backup.exists() {
        return Err(invalid(
            "a recoverable Agent backup already exists; refusing to overwrite it",
        ));
    }
    let journal_path = updates.join("publication.json");
    let staged_bin = staged.path().join("bin");
    fs::create_dir(&staged_bin)?;
    set_private_directory(&staged_bin)?;
    for name in package_files(&request.target) {
        let source = staged.path().join(&name);
        let dest = staged_bin.join(&name);
        fs::rename(source, dest)?;
    }
    validate_installed(
        &staged_bin,
        &InstallMetadata {
            format: 1,
            target: request.target.clone(),
            installed_version: request.version.clone(),
            installed_package_sha256: request.archive_sha256.clone(),
            installed_files: manifest.files.clone(),
        },
        &request.target,
    )?;

    let journal = PublicationJournal {
        format: 1,
        backup: backup
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid Agent backup path"))?
            .to_owned(),
        old_metadata: old_metadata.clone(),
    };
    write_atomic_new(
        &journal_path,
        &serde_json::to_vec(&journal).map_err(io::Error::other)?,
    )?;

    fs::rename(bin_root, &backup)?;
    if let Err(error) = fs::rename(&staged_bin, bin_root) {
        let rollback = fs::rename(&backup, bin_root);
        if let Err(rollback_error) = rollback {
            return Err(io::Error::other(format!(
                "Agent publication failed ({error}); rollback failed ({rollback_error}); old executable remains at {}",
                backup.display()
            )));
        }
        sync_directory(root)?;
        sync_directory(&updates)?;
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    sync_directory(root)?;
    sync_directory(&updates)?;
    let metadata = InstallMetadata {
        format: 1,
        target: request.target.clone(),
        installed_version: request.version.clone(),
        installed_package_sha256: request.archive_sha256.clone(),
        installed_files: manifest.files,
    };
    let metadata_bytes = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
    if let Err(error) = write_atomic(metadata_path, &metadata_bytes) {
        let failed = root
            .join(".updates")
            .join(format!("failed-{}", request.archive_sha256));
        let preserve_new = fs::rename(bin_root, &failed);
        if let Err(preserve_error) = preserve_new {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); new files could not be preserved ({preserve_error}) and old backup remains at {}",
                backup.display()
            )));
        }
        let restore_old = fs::rename(&backup, bin_root);
        if let Err(rollback_error) = restore_old {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); rollback failed ({rollback_error}); preserve files in {} and {}",
                backup.display(),
                failed.display()
            )));
        }
        sync_directory(root)?;
        sync_directory(&updates)?;
        if let Err(metadata_error) = write_atomic(
            metadata_path,
            &serde_json::to_vec_pretty(&old_metadata).map_err(io::Error::other)?,
        ) {
            return Err(io::Error::other(format!(
                "Agent metadata publication failed ({error}); old binary was restored but old metadata restoration failed ({metadata_error}); journal remains at {}",
                journal_path.display()
            )));
        }
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    let verification = read_install_metadata(metadata_path).and_then(|installed| {
        if installed != metadata {
            return Err(invalid(
                "installed Agent metadata differs from the selected package",
            ));
        }
        validate_installed(bin_root, &installed, &request.target)
    });
    if let Err(error) = verification {
        let failed = updates.join(format!("verification-failed-{}", request.archive_sha256));
        fs::rename(bin_root, &failed).map_err(|preserve_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); new files could not be preserved ({preserve_error}); old backup remains at {}",
                backup.display()
            ))
        })?;
        fs::rename(&backup, bin_root).map_err(|rollback_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); rollback failed ({rollback_error}); preserve files in {} and {}",
                backup.display(),
                failed.display()
            ))
        })?;
        write_atomic(
            metadata_path,
            &serde_json::to_vec_pretty(&old_metadata).map_err(io::Error::other)?,
        )
        .map_err(|metadata_error| {
            io::Error::other(format!(
                "installed Agent verification failed ({error}); old binary was restored but metadata rollback failed ({metadata_error}); journal remains at {}",
                journal_path.display()
            ))
        })?;
        fs::remove_file(&journal_path)?;
        return Err(error);
    }
    File::open(root)?.sync_all()?;
    File::open(&updates)?.sync_all()?;
    fs::remove_file(journal_path)?;
    File::open(&updates)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn recover_interrupted_publication(root: &Path) -> io::Result<()> {
    let updates = root.join(".updates");
    match fs::symlink_metadata(&updates) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(metadata)
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata) =>
        {
            return Err(invalid("Agent update recovery directory is unsafe"));
        }
        Ok(metadata) => validate_private_directory(&updates, &metadata)?,
    }
    let journal_path = updates.join("publication.json");
    match fs::symlink_metadata(&journal_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || is_reparse_point(&metadata) =>
        {
            Err(invalid("Agent update recovery journal is unsafe"))
        }
        Ok(_) => {
            let file = open_private_file(&journal_path, false)?;
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err(invalid("Agent recovery journal exceeds its size limit"));
            }
            let journal: PublicationJournal = serde_json::from_slice(&bytes).map_err(|error| {
                invalid_owned(format!("invalid Agent recovery journal: {error}"))
            })?;
            if journal.format != 1
                || !journal.backup.starts_with("backup-")
                || Path::new(&journal.backup).components().count() != 1
                || !matches!(
                    Path::new(&journal.backup).components().next(),
                    Some(Component::Normal(_))
                )
                || !supported_targets().contains(&journal.old_metadata.target.as_str())
                || !target_matches_runtime(&journal.old_metadata.target)
            {
                return Err(invalid(
                    "Agent recovery journal contains an unsafe backup path",
                ));
            }
            let backup = updates.join(&journal.backup);
            let bin = root.join("bin");
            let metadata_path = root.join(INSTALL_METADATA);
            let installed = read_install_metadata(&metadata_path).and_then(|metadata| {
                validate_installed(&bin, &metadata, &journal.old_metadata.target).map(|()| metadata)
            });
            if installed.is_ok() {
                fs::remove_file(&journal_path)?;
                File::open(&updates)?.sync_all()?;
                return Ok(());
            }
            if validate_installed(&bin, &journal.old_metadata, &journal.old_metadata.target).is_ok()
            {
                write_atomic(
                    &metadata_path,
                    &serde_json::to_vec_pretty(&journal.old_metadata).map_err(io::Error::other)?,
                )?;
                fs::remove_file(&journal_path)?;
                File::open(&updates)?.sync_all()?;
                return Ok(());
            }
            if !backup.exists() {
                return Err(io::Error::other(format!(
                    "Agent update recovery cannot validate installed files or find backup {}; journal remains at {}",
                    backup.display(),
                    journal_path.display()
                )));
            }
            validate_installed(&backup, &journal.old_metadata, &journal.old_metadata.target)
                .map_err(|error| io::Error::other(format!(
                    "Agent update recovery backup {} failed integrity validation ({error}); journal remains at {}",
                    backup.display(), journal_path.display()
                )))?;
            if bin.exists() {
                let failed = updates.join(format!("recovery-failed-{}", std::process::id()));
                if failed.exists() {
                    return Err(invalid(
                        "Agent recovery destination already exists; backup and journal preserved",
                    ));
                }
                fs::rename(&bin, &failed)?;
                sync_directory(root)?;
                sync_directory(&updates)?;
            }
            fs::rename(&backup, &bin)?;
            sync_directory(root)?;
            sync_directory(&updates)?;
            write_atomic(
                &metadata_path,
                &serde_json::to_vec_pretty(&journal.old_metadata).map_err(io::Error::other)?,
            )?;
            File::open(root)?.sync_all()?;
            fs::remove_file(&journal_path)?;
            File::open(&updates)?.sync_all()?;
            Ok(())
        }
    }
}

fn file_identities(root: &Path, names: &[String]) -> io::Result<BTreeMap<String, FileIdentity>> {
    let mut result = BTreeMap::new();
    let mut total_size = 0_u64;
    for name in names {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid("installed Agent package file is missing or unsafe"));
        }
        if metadata.len() > MAX_ENTRY_BYTES {
            return Err(invalid(
                "installed Agent package file exceeds its size limit",
            ));
        }
        total_size = total_size
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("installed Agent package size overflow"))?;
        if total_size > MAX_TOTAL_BYTES {
            return Err(invalid(
                "installed Agent package exceeds its total size limit",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(invalid(
                    "installed Agent package file has an unexpected hard link",
                ));
            }
        }
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut HashWriter(&mut hasher))?;
        result.insert(
            name.clone(),
            FileIdentity {
                size,
                sha256: format!("{:x}", hasher.finalize()),
            },
        );
    }
    Ok(result)
}

struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_file(path: &Path, max_size: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 || size > max_size {
        return Err(invalid("Agent archive exceeds its size limit"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn open_private_file(path: &Path, create: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let metadata = fs::symlink_metadata(path);
    if let Ok(metadata) = metadata
        && (!metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata))
    {
        return Err(invalid(
            "Agent updater state file is not a safe regular file",
        ));
    }
    options.open(path)
}

#[cfg(not(windows))]
fn open_new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

#[cfg(not(windows))]
fn write_atomic_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("journal path has no parent"))?;
    let temporary = parent.join(format!(".publication-{}.tmp", std::process::id()));
    let mut file = open_new_private_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("metadata path has no parent"))?;
    let temporary = parent.join(format!(".install-{}.tmp", std::process::id()));
    let mut file = open_new_private_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(windows))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            validate_private_directory(path, &metadata)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(invalid("Agent update directory is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and reads only the current process identity.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(invalid("Agent update directory is not privately owned"));
        }
    }
    let _ = path;
    Ok(())
}

fn set_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    set_windows_private_acl(path, true)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

fn set_staged_file_permissions(path: &Path, relative: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if relative == EXECUTABLE_BASE {
            0o700
        } else {
            0o600
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let _ = relative;
        set_windows_private_acl(path, false)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (path, relative);
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn validate_windows_private_acl(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_permissions::constants::{AceType, SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::GetNamedSecurityInfo;

    if metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid("Windows updater path is a reparse point"));
    }
    let descriptor = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner,
    )
    .map_err(io::Error::other)?;
    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    if descriptor.owner() != Some(current.as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater path is not owned by the current user",
        ));
    }
    let sddl = windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
        &descriptor,
        SecurityInformation::Dacl,
    )
    .map_err(io::Error::other)?;
    if !sddl.to_string_lossy().starts_with("D:P") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Windows updater ACL inherits permissions",
        ));
    }
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("Windows updater path has no DACL"))?;
    for index in 0..dacl.len() {
        let ace = dacl
            .get_ace(index)
            .ok_or_else(|| invalid("Windows updater DACL entry is unreadable"))?;
        if matches!(
            ace.ace_type(),
            AceType::ACCESS_ALLOWED_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ) && ace.sid() != Some(current.as_ref())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows updater ACL grants access to a foreign owner",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_windows_private_acl(path: &Path, directory: bool) -> io::Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current =
        windows_permissions::utilities::current_process_sid().map_err(io::Error::other)?;
    let current = ConvertSidToStringSid(&current).map_err(io::Error::other)?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!("D:P(A;{inheritance};FA;;;{})", current.to_string_lossy());
    let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().map_err(io::Error::other)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| invalid("cannot create private Windows updater DACL"))?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(io::Error::other)?;
    let metadata = fs::symlink_metadata(path)?;
    validate_windows_private_acl(path, &metadata)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
