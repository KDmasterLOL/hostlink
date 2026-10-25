//! Exact, local, Agent-only package updates.
//!
//! Updates are serialized with an OS file lock, staged under the user-owned install root,
//! and published only after the selected archive, target, version, and file manifest agree.
//! Windows publication is deliberately refused until the stopped-process launcher handoff is
//! integrated; replacing a running Windows executable is never attempted here.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use zip::ZipArchive;

const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const PACKAGE_MANIFEST: &str = "manifest.json";
const INSTALL_METADATA: &str = "install.json";
const EXECUTABLE_BASE: &str = "hostlink-agent";

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
    installed_files: BTreeMap<String, FileIdentity>,
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

    let (manifest, staged_files) = validate_and_stage_archive(request, &archive_path)?;
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
    Ok(canonical_archive)
}

fn validate_and_stage_archive(
    request: &AgentUpdateRequest,
    archive_path: &Path,
) -> io::Result<(PackageManifest, tempfile::TempDir)> {
    let stage = tempfile::Builder::new()
        .prefix(".agent-update-")
        .tempdir_in(&request.install_root)?;
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
    if hash_file(&staged_archive, MAX_ARCHIVE_BYTES)? != request.archive_sha256 {
        return Err(invalid("selected Agent archive SHA-256 does not match"));
    }
    let mut archive = ZipArchive::new(File::open(&staged_archive)?)
        .map_err(|error| invalid_owned(format!("invalid Agent ZIP archive: {error}")))?;
    let prefix = format!("hostlink-agent-{}/", request.target);
    let expected = package_files(&request.target)
        .into_iter()
        .chain(std::iter::once(PACKAGE_MANIFEST.to_owned()))
        .collect::<BTreeSet<_>>();
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
        || manifest.target != request.target
        || manifest.version != request.version
    {
        return Err(invalid(
            "Agent package manifest does not match the selected version and target",
        ));
    }
    if manifest.files != identities
        || manifest.files.keys().cloned().collect::<BTreeSet<_>>()
            != package_files(&request.target).into_iter().collect()
    {
        return Err(invalid(
            "Agent package manifest file identities do not match the archive",
        ));
    }
    Ok((manifest, stage))
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
    #[cfg(not(unix))]
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
    #[cfg(not(unix))]
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
