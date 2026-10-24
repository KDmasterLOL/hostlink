//! Exact ZIP package updater backed by `self_update`.

use crate::jobs;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use hostlink_core::{
    Sha256Digest, acquire_exclusive_file_lock, read_file_bounded, write_file_atomically,
};
use self_update::backends::custom::Update;
use self_update::http_client::{HeaderMap, HttpClient, HttpResponse};
use self_update::{Checksum, Download, Release, ReleaseAsset, ReleaseSource, ReleaseStatus};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ureq::http::Uri;

const UPDATE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const UPDATE_LOCK_POLL: Duration = Duration::from_millis(20);
const INSTALL_METADATA_MAX_BYTES: usize = 1024 * 1024;
const LOCAL_ARCHIVE_URL_PREFIX: &str = "onec-local://archive/";
const DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const DIRECT_ARCHIVE_MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const DIRECT_ARCHIVE_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// Observable outcome of one exact runtime package update attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeUpdateOutcome {
    /// Update was skipped before network access because durable jobs are active.
    DeferredActiveJobs {
        /// Durable job identifiers that currently block runtime replacement.
        job_ids: Vec<String>,
    },
    /// The direct package archive digest is already installed.
    DirectUpToDate {
        /// Ordinary package version recorded for the installed archive.
        package_version: String,
        /// Canonical digest of the selected package archive.
        archive_sha256: String,
    },
    /// A directly selected package archive replaced the immutable runtime bundle.
    DirectUpdated {
        /// Ordinary package version of the installed archive.
        package_version: String,
        /// Canonical digest of the installed package archive.
        archive_sha256: String,
    },
}

/// Request to install one infrastructure-selected exact package archive.
#[derive(Debug, Clone)]
pub struct DirectPackageUpdateRequest {
    /// Toolkit root containing `install.json`, jobs, lock and immutable runtime.
    pub root: PathBuf,
    /// Exact HTTPS URL of the target-specific ZIP archive, or `None` for a staged local file.
    pub archive_url: Option<String>,
    /// Absolute staged ZIP path inside the toolkit root, or `None` for HTTPS download.
    pub archive_file: Option<PathBuf>,
    /// Externally trusted SHA-256 of the exact ZIP bytes.
    pub archive_sha256: String,
    /// Ordinary package semver selected by the controller.
    pub package_version: String,
    /// Exact supported Rust target triple selected by the controller.
    pub target: String,
}

/// Request to install one independently selected HostLink Agent-only archive.
#[derive(Debug, Clone)]
pub struct AgentPackageUpdateRequest {
    /// User-owned HostLink root containing the job store and update lock.
    pub root: PathBuf,
    /// Exact externally selected HTTPS URL, or `None` for a root-contained ZIP.
    pub archive_url: Option<String>,
    /// Absolute ZIP path contained by `root`, or `None` for an HTTPS download.
    pub archive_file: Option<PathBuf>,
    /// Trusted SHA-256 of the exact ZIP bytes.
    pub archive_sha256: String,
    /// Externally selected package semantic version.
    pub package_version: String,
    /// Externally selected Rust target triple.
    pub target: String,
}

/// Read-only result of checking whether a runtime update may begin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeUpdatePreflightOutcome {
    /// No durable job currently requires the resident runtime to remain stable.
    Ready,
    /// Durable jobs are active, so routine update should be retried later.
    DeferredActiveJobs {
        /// Durable job identifiers currently blocking the update.
        job_ids: Vec<String>,
    },
}

/// Check active durable jobs without downloading or mutating runtime state.
///
/// This is an advisory preflight used before service/agent quiescence. The actual updater repeats
/// the same check after acquiring the managed-root writer lock.
///
/// # Errors
///
/// Returns an I/O error when durable job state cannot be inspected safely.
pub fn preflight_runtime_update(root: &Path) -> io::Result<RuntimeUpdatePreflightOutcome> {
    let active_jobs = jobs::active_ids(&root.join("jobs"))?;
    if active_jobs.is_empty() {
        Ok(RuntimeUpdatePreflightOutcome::Ready)
    } else {
        Ok(RuntimeUpdatePreflightOutcome::DeferredActiveJobs {
            job_ids: active_jobs,
        })
    }
}

/// Install one exact package archive selected by trusted infrastructure.
///
/// The URL or staged archive and external digest are the complete selection. The exact ZIP is
/// bounded, checksum-checked,
/// and structurally preflighted before `self_update` can extract or replace the runtime. Existing
/// installed target identity and active-job/update-lock guards apply.
///
/// # Errors
///
/// Returns an error if the request does not match the installed target, the URL/version/digest is
/// invalid, active-job state cannot be read, transport or checksum verification fails, or safe
/// bundle installation/metadata publication fails.
pub fn update_direct_package(
    request: &DirectPackageUpdateRequest,
) -> io::Result<RuntimeUpdateOutcome> {
    let archive_sha256 = Sha256Digest::from_str(&request.archive_sha256)
        .map_err(|_| invalid("archive_sha256 must contain 64 hex characters"))?;
    validate_direct_package(request)?;

    let _writer = acquire_exclusive_file_lock(
        request.root.join("update.lock"),
        UPDATE_LOCK_TIMEOUT,
        UPDATE_LOCK_POLL,
    )?;
    if let RuntimeUpdatePreflightOutcome::DeferredActiveJobs { job_ids } =
        preflight_runtime_update(&request.root)?
    {
        return Ok(RuntimeUpdateOutcome::DeferredActiveJobs { job_ids });
    }

    let metadata_path = request.root.join("install.json");
    let metadata_bytes = read_file_bounded(&metadata_path, INSTALL_METADATA_MAX_BYTES)?;
    let mut metadata: Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| invalid_owned(format!("install.json is invalid: {error}")))?;
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| invalid("install.json root must be a JSON object"))?;
    let installed_target = required_string(object, "target")?;
    if installed_target != request.target {
        return Err(invalid(
            "selected target does not match install.json target",
        ));
    }

    let canonical_digest = archive_sha256.to_string();
    if object
        .get("installed_package_sha256")
        .and_then(Value::as_str)
        == Some(canonical_digest.as_str())
    {
        let installed_version = required_string(object, "installed_version")?;
        // The Windows bootstrap records `onec --version`, which includes a
        // `+src...` build fingerprint. The controller selects the ordinary
        // package semver; the exact archive SHA above already binds the bytes.
        let mut installed_semver = semver::Version::parse(installed_version)
            .map_err(|_| invalid("installed package version is not semver"))?;
        let mut requested_semver = semver::Version::parse(&request.package_version)
            .map_err(|_| invalid("requested package version is not semver"))?;
        installed_semver.build = semver::BuildMetadata::EMPTY;
        requested_semver.build = semver::BuildMetadata::EMPTY;
        if installed_semver != requested_semver {
            return Err(invalid(
                "selected package version conflicts with the installed archive digest",
            ));
        }
        let recorded_files = object
            .get("installed_runtime_files")
            .ok_or_else(|| {
                invalid(
                    "installed runtime integrity metadata is missing; run the direct installer to restore bin before retrying unattended updates",
                )
            })?;
        let actual_files = runtime_file_identities(&request.root, &required_runtime_files())?;
        if recorded_files != &actual_files {
            return Err(invalid(
                "installed runtime files do not match install.json integrity metadata; run the direct installer to restore bin before retrying unattended updates",
            ));
        }
        return Ok(RuntimeUpdateOutcome::DirectUpToDate {
            package_version: request.package_version.clone(),
            archive_sha256: canonical_digest,
        });
    }

    let mut staged_archive = tempfile::tempfile_in(&request.root)?;
    if let Some(archive_url) = &request.archive_url {
        let mut download = Download::from_url(archive_url);
        download
            .timeout(Duration::from_secs(30))
            .max_download_size(DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES);
        download
            .download_to(&mut staged_archive)
            .map_err(update_error)?;
    } else {
        let archive_file = request.archive_file.as_deref().ok_or_else(|| {
            invalid("direct update requires an archive URL or local archive file")
        })?;
        let mut source = open_scoped_archive(&request.root, archive_file)?;
        copy_archive_bounded(&mut source, &mut staged_archive)?;
    }
    verify_open_archive_digest(&mut staged_archive, &archive_sha256)?;
    validate_direct_archive(&mut staged_archive, &request.target)?;
    let (archive_url, local_archive) = if let Some(archive_url) = &request.archive_url {
        (archive_url.clone(), Some(staged_archive))
    } else {
        (
            format!("{LOCAL_ARCHIVE_URL_PREFIX}{archive_sha256}"),
            Some(staged_archive),
        )
    };
    let exact = direct_bundle_request(request, archive_sha256, archive_url);
    install_exact_bundle_unlocked_with_local_file(&exact, local_archive)?;

    object.insert(
        "installed_version".to_owned(),
        Value::String(request.package_version.clone()),
    );
    object.insert(
        "installed_package_sha256".to_owned(),
        Value::String(canonical_digest.clone()),
    );
    object.insert(
        "installed_runtime_files".to_owned(),
        runtime_file_identities(&request.root, &required_runtime_files())?,
    );
    // Clear stale legacy identity so metadata describes only the exact installed package digest.
    object.remove("installed_release_id");
    let mut bytes = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
    bytes.push(b'\n');
    write_file_atomically(&metadata_path, &bytes)?;

    Ok(RuntimeUpdateOutcome::DirectUpdated {
        package_version: request.package_version.clone(),
        archive_sha256: canonical_digest,
    })
}

/// Install or verify an Agent-only package below `root/hostlink-agent`.
///
/// Existing Toolkit files remain outside this isolated subtree. An identical package is a no-op
/// only when every installed package file still matches its recorded size and SHA-256.
///
/// # Errors
///
/// Returns an error for unsafe roots or archive paths, invalid selection metadata, archive
/// inventory/digest failures, target conflicts, tampered installed files, or publication errors.
pub fn update_agent_package(
    request: &AgentPackageUpdateRequest,
) -> io::Result<RuntimeUpdateOutcome> {
    let digest = Sha256Digest::from_str(&request.archive_sha256)
        .map_err(|_| invalid("archive_sha256 must contain 64 hex characters"))?;
    validate_agent_package(request)?;
    validate_agent_install_scope(&request.root)?;
    let install_root = request.root.join("hostlink-agent");
    validate_agent_install_subtree(&request.root, &install_root)?;

    let _writer = acquire_exclusive_file_lock(
        request.root.join("update.lock"),
        UPDATE_LOCK_TIMEOUT,
        UPDATE_LOCK_POLL,
    )?;
    if let RuntimeUpdatePreflightOutcome::DeferredActiveJobs { job_ids } =
        preflight_runtime_update(&request.root)?
    {
        return Ok(RuntimeUpdateOutcome::DeferredActiveJobs { job_ids });
    }

    // Validate a local selection even when the installed digest later proves to be a no-op.
    let validated_local_archive = if let Some(source_path) = request.archive_file.as_deref() {
        let mut staged = tempfile::tempfile_in(&request.root)?;
        let mut source = open_scoped_archive(&request.root, source_path)?;
        copy_archive_bounded(&mut source, &mut staged)?;
        verify_open_archive_digest(&mut staged, &digest)?;
        validate_agent_archive(&mut staged, &request.target)?;
        Some(staged)
    } else {
        None
    };

    let metadata_path = install_root.join("install.json");
    let has_metadata = match std::fs::symlink_metadata(&metadata_path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && !is_reparse_point(&metadata) =>
        {
            true
        }
        Ok(_) => {
            return Err(invalid(
                "HostLink Agent install metadata is not a safe regular file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if has_metadata {
        let metadata_file = open_scoped_archive(&request.root, &metadata_path)?;
        let mut metadata_bytes = Vec::new();
        metadata_file
            .take(INSTALL_METADATA_MAX_BYTES as u64 + 1)
            .read_to_end(&mut metadata_bytes)?;
        if metadata_bytes.len() > INSTALL_METADATA_MAX_BYTES {
            return Err(invalid(
                "HostLink Agent install metadata exceeds size limit",
            ));
        }
        let metadata: Value = serde_json::from_slice(&metadata_bytes).map_err(|error| {
            invalid_owned(format!(
                "HostLink Agent install metadata is invalid: {error}"
            ))
        })?;
        let object = metadata
            .as_object()
            .ok_or_else(|| invalid("HostLink Agent install metadata must be a JSON object"))?;
        if required_string(object, "target")? != request.target {
            return Err(invalid(
                "selected target does not match installed HostLink Agent target",
            ));
        }
        let expected = object.get("installed_files").ok_or_else(|| {
            invalid("installed HostLink Agent file integrity metadata is missing")
        })?;
        let actual = package_file_identities(
            &install_root.join("bin"),
            &agent_package_files(&request.target),
        )?;
        if expected != &actual {
            return Err(invalid(
                "installed HostLink Agent files do not match install metadata",
            ));
        }
        if object
            .get("installed_package_sha256")
            .and_then(Value::as_str)
            == Some(digest.to_string().as_str())
        {
            let installed_version = required_string(object, "installed_version")?;
            if semver::Version::parse(installed_version).ok()
                != semver::Version::parse(&request.package_version).ok()
            {
                return Err(invalid(
                    "selected package version conflicts with the installed archive digest",
                ));
            }
            return Ok(RuntimeUpdateOutcome::DirectUpToDate {
                package_version: request.package_version.clone(),
                archive_sha256: digest.to_string(),
            });
        }
    }

    let mut staged_archive = if let Some(staged) = validated_local_archive {
        staged
    } else {
        let mut staged = tempfile::tempfile_in(&request.root)?;
        let url = request
            .archive_url
            .as_deref()
            .ok_or_else(|| invalid("Agent update requires an archive source"))?;
        let mut download = Download::from_url(url);
        download
            .timeout(Duration::from_secs(30))
            .max_download_size(DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES);
        download.download_to(&mut staged).map_err(update_error)?;
        staged
    };
    verify_open_archive_digest(&mut staged_archive, &digest)?;
    validate_agent_archive(&mut staged_archive, &request.target)?;

    // self_update publishes a staged directory by rename and requires its parent to exist.
    std::fs::create_dir_all(install_root.join("bin"))?;
    validate_agent_install_subtree(&request.root, &install_root)?;

    let archive_url = request
        .archive_url
        .clone()
        .unwrap_or_else(|| format!("{LOCAL_ARCHIVE_URL_PREFIX}{digest}"));
    let exact = ExactBundleUpdateRequest {
        package_version: request.package_version.clone(),
        release_id: format!("direct:{}:{digest}", request.package_version),
        target: request.target.clone(),
        archive_url,
        archive_name: format!("hostlink-agent-{}.zip", request.target),
        archive_sha256: digest,
        bundle_path_in_archive: format!("hostlink-agent-{}", request.target),
        bundle_install_path: install_root.join("bin"),
        binary_name: "hostlink-agent".to_owned(),
        required_files: agent_package_files(&request.target),
    };
    install_exact_bundle_unlocked_with_local_file(&exact, Some(staged_archive))?;
    let metadata = serde_json::json!({
        "format": 1,
        "target": request.target,
        "installed_version": request.package_version,
        "installed_package_sha256": digest.to_string(),
        "installed_files": package_file_identities(&install_root.join("bin"), &agent_package_files(&request.target))?,
    });
    let mut bytes = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
    bytes.push(b'\n');
    write_file_atomically(&metadata_path, &bytes)?;
    Ok(RuntimeUpdateOutcome::DirectUpdated {
        package_version: request.package_version.clone(),
        archive_sha256: digest.to_string(),
    })
}

const SUPPORTED_AGENT_TARGETS: [&str; 4] = [
    "x86_64-pc-windows-msvc",
    "x86_64-win7-windows-msvc",
    "i686-win7-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

fn agent_package_files(target: &str) -> Vec<PathBuf> {
    let executable = if target.contains("windows") {
        "hostlink-agent.exe"
    } else {
        "hostlink-agent"
    };
    let mut files = vec![PathBuf::from(executable)];
    if target.contains("windows") {
        files.extend(
            [
                "Install-HostLink-Agent.ps1",
                "Run-HostLink-Agent.ps1",
                "Update-HostLink-Agent.ps1",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }
    files
}

fn validate_agent_package(request: &AgentPackageUpdateRequest) -> io::Result<()> {
    if !SUPPORTED_AGENT_TARGETS.contains(&request.target.as_str()) {
        return Err(invalid("unsupported Agent package target triple"));
    }
    if !target_matches_running_agent(&request.target) {
        return Err(invalid(
            "selected Agent target does not match this Agent runtime OS and architecture",
        ));
    }
    validate_package_version(&request.package_version)?;
    if !request.root.is_absolute() || request.root.as_os_str().is_empty() {
        return Err(invalid("Agent root must be an absolute non-empty path"));
    }
    match (&request.archive_url, &request.archive_file) {
        (Some(url), None) => validate_direct_archive_url(url)?,
        (None, Some(path))
            if path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)) => {}
        _ => {
            return Err(invalid(
                "Agent update requires exactly one absolute root-contained archive source",
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn target_matches_running_agent(target: &str) -> bool {
    matches!(
        target,
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc"
    )
}

#[cfg(all(target_os = "windows", target_arch = "x86"))]
fn target_matches_running_agent(target: &str) -> bool {
    target == "i686-win7-windows-msvc"
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn target_matches_running_agent(target: &str) -> bool {
    target == "x86_64-unknown-linux-gnu"
}

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86"),
    all(target_os = "linux", target_arch = "x86_64")
)))]
fn target_matches_running_agent(_target: &str) -> bool {
    false
}

fn validate_agent_install_scope(root: &Path) -> io::Result<()> {
    #[cfg(all(windows, not(test)))]
    {
        let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
            invalid("LOCALAPPDATA is required for user-scoped HostLink Agent installation")
        })?;
        let expected = Path::new(&local_app_data).join("HostLink").join("Agent");
        if std::fs::canonicalize(root)? != std::fs::canonicalize(expected)? {
            return Err(invalid(
                "HostLink Agent root must be the current user's LOCALAPPDATA/HostLink/Agent directory",
            ));
        }
    }
    #[cfg(not(all(windows, not(test))))]
    let _ = root;
    Ok(())
}

fn validate_agent_install_subtree(root: &Path, install_root: &Path) -> io::Result<()> {
    for path in [root, install_root, &install_root.join("bin")] {
        match std::fs::symlink_metadata(path) {
            Ok(meta)
                if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse_point(&meta) =>
            {
                return Err(invalid(
                    "HostLink Agent install path contains an unsafe directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_agent_archive(file: &mut File, target: &str) -> io::Result<()> {
    validate_exact_archive(
        file,
        &format!("hostlink-agent-{target}"),
        &agent_package_files(target),
    )
}

fn package_file_identities(root: &Path, required: &[PathBuf]) -> io::Result<Value> {
    let mut identities = serde_json::Map::new();
    for relative in required {
        let path = root.join(relative);
        let mut file = open_regular_file_no_links(&path)?;
        let size = file.metadata()?.len();
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        identities.insert(
            relative.to_string_lossy().into_owned(),
            serde_json::json!({"size": size, "sha256": format!("{:x}", hasher.finalize())}),
        );
    }
    Ok(Value::Object(identities))
}

fn open_regular_file_no_links(path: &Path) -> io::Result<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(invalid(
            "installed HostLink Agent file is missing or unsafe",
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("installed HostLink Agent file is not regular"));
    }
    Ok(file)
}

fn validate_direct_package(request: &DirectPackageUpdateRequest) -> io::Result<()> {
    if !SUPPORTED_TARGETS.contains(&request.target.as_str()) {
        return Err(invalid("unsupported package target triple"));
    }
    validate_package_version(&request.package_version)?;
    match (&request.archive_url, &request.archive_file) {
        (Some(archive_url), None) => validate_direct_archive_url(archive_url)?,
        (None, Some(archive_file)) => {
            if !archive_file.is_absolute()
                || archive_file
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(invalid(
                    "archive_file must be absolute and must not contain parent traversal",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "direct update requires exactly one of archive_url or archive_file",
            ));
        }
    }
    if request.root.as_os_str().is_empty() {
        return Err(invalid("toolkit root is empty"));
    }
    Ok(())
}

fn direct_bundle_request(
    request: &DirectPackageUpdateRequest,
    archive_sha256: Sha256Digest,
    archive_url: String,
) -> ExactBundleUpdateRequest {
    ExactBundleUpdateRequest {
        package_version: request.package_version.clone(),
        release_id: format!("direct:{}:{}", request.package_version, archive_sha256),
        target: request.target.clone(),
        archive_url,
        archive_name: format!("onec-toolkit-{}.zip", request.target),
        archive_sha256,
        bundle_path_in_archive: format!("onec-toolkit-{}", request.target),
        bundle_install_path: request.root.join("bin"),
        binary_name: "onec-toolkit".to_owned(),
        required_files: required_runtime_files(),
    }
}

const SUPPORTED_TARGETS: [&str; 3] = [
    "x86_64-pc-windows-msvc",
    "x86_64-win7-windows-msvc",
    "i686-win7-windows-msvc",
];

fn validate_package_version(version: &str) -> io::Result<()> {
    semver::Version::parse(version)
        .map(|_| ())
        .map_err(|_| invalid("package_version must be an ordinary semver version"))
}

fn required_runtime_files() -> Vec<PathBuf> {
    [
        "onec-agent.exe",
        "onec.exe",
        "Run-OnecAgent.ps1",
        "Update-OnecToolkit.ps1",
        "onec-toolkit-update.cmd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// Read back every required installed runtime file and record its exact byte identity.
///
/// The direct archive digest identifies the downloaded ZIP, but cannot by itself prove that the
/// published files in `bin/` still contain the bytes extracted from that archive. These per-file
/// size and digest records are captured only after successful bundle publication and checked
/// under the same update lock before returning `DirectUpToDate`.
fn runtime_file_identities(root: &Path, required_files: &[PathBuf]) -> io::Result<Value> {
    let mut identities = serde_json::Map::new();
    for relative in required_files {
        let path = root.join("bin").join(relative);
        let mut file = open_scoped_archive(root, &path).map_err(|error| {
            invalid_owned(format!(
                "installed runtime file {} is missing or unsafe: {error}; run the direct installer to restore bin before retrying unattended updates",
                relative.display()
            ))
        })?;
        let size = file.metadata().map_err(|error| {
            invalid_owned(format!(
                "cannot read installed runtime file {}: {error}; run the direct installer to restore bin before retrying unattended updates",
                relative.display()
            ))
        })?.len();
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                invalid_owned(format!(
                    "cannot read installed runtime file {}: {error}; run the direct installer to restore bin before retrying unattended updates",
                    relative.display()
                ))
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        identities.insert(
            relative.to_string_lossy().into_owned(),
            serde_json::json!({
                "size": size,
                "sha256": format!("{:x}", hasher.finalize()),
            }),
        );
    }
    Ok(Value::Object(identities))
}

fn validate_direct_archive_url(value: &str) -> io::Result<()> {
    let uri = validate_update_uri(value, "archive URL")?;
    if !uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        return Err(invalid("direct package archive URL must use HTTPS"));
    }
    let path = uri.path_and_query().map_or("/", |value| value.path());
    if path.contains('\\')
        || path.to_ascii_lowercase().contains("%2f")
        || path.to_ascii_lowercase().contains("%5c")
        || path.split('/').any(|segment| {
            let decoded_dots = segment.replace("%2e", ".").replace("%2E", ".");
            decoded_dots == "." || decoded_dots == ".."
        })
    {
        return Err(invalid(
            "direct package archive URL has an unsafe path scope",
        ));
    }
    Ok(())
}

fn open_scoped_archive(root: &Path, archive_file: &Path) -> io::Result<File> {
    if !root.is_absolute()
        || !archive_file.is_absolute()
        || archive_file
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "archive_file must be absolute and must not contain parent traversal",
        ));
    }
    let canonical_root = std::fs::canonicalize(root)?;
    let relative = archive_file
        .strip_prefix(root)
        .map_err(|_| invalid("archive_file must be inside the canonical toolkit root"))?;
    let canonical_archive = std::fs::canonicalize(archive_file)
        .map_err(|_| invalid("archive_file must be inside the canonical toolkit root"))?;
    if !canonical_archive.starts_with(&canonical_root) {
        return Err(invalid(
            "archive_file must be inside the canonical toolkit root",
        ));
    }
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(invalid("archive_file path is not a confined relative path"));
    }

    let mut candidate = canonical_root.clone();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        candidate.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid(
                "archive_file path must not contain symlinks or reparse points",
            ));
        }
        let last = index + 1 == components.len();
        if (last && !metadata.is_file()) || (!last && !metadata.is_dir()) {
            return Err(invalid(
                "archive_file must resolve to a regular file inside the toolkit root",
            ));
        }
    }

    let root_dir = Dir::open_ambient_dir(&canonical_root, ambient_authority())?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = root_dir.open_with(relative, &options)?.into_std();
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(invalid("archive_file is not a regular non-reparse file"));
    }
    Ok(file)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn verify_open_archive_digest(file: &mut File, expected: &Sha256Digest) -> io::Result<()> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))?;
    let computed = Sha256Digest::from_str(&format!("{:x}", hasher.finalize()))
        .map_err(|_| io::Error::other("computed archive digest is invalid"))?;
    if &computed != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged archive SHA-256 does not match the trusted digest",
        ));
    }
    Ok(())
}

fn copy_archive_bounded(source: &mut File, destination: &mut File) -> io::Result<()> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or_else(|| invalid("direct package archive size overflow"))?;
        if copied > DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES {
            return Err(invalid(
                "direct package archive exceeds compressed size limit",
            ));
        }
        std::io::Write::write_all(destination, &buffer[..count])?;
    }
    destination.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// Validate the exact ZIP that will be passed to self_update, including decoded bytes and CRCs.
fn validate_direct_archive(file: &mut File, target: &str) -> io::Result<()> {
    let archive_size = file.metadata()?.len();
    if archive_size == 0 || archive_size > DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES {
        return Err(invalid(
            "direct package archive exceeds compressed size limit",
        ));
    }
    let package = format!("onec-toolkit-{target}");
    validate_exact_archive(file, &package, &required_runtime_files())
}

fn validate_exact_archive(
    file: &mut File,
    package: &str,
    required_files: &[PathBuf],
) -> io::Result<()> {
    let archive_size = file.metadata()?.len();
    if archive_size == 0 || archive_size > DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES {
        return Err(invalid("package archive exceeds compressed size limit"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| invalid_owned(error.to_string()))?;
    let expected = required_files
        .iter()
        .map(|path| format!("{package}/{}", path.to_string_lossy()))
        .collect::<std::collections::BTreeSet<_>>();
    if archive.len() != expected.len() {
        return Err(invalid(
            "package archive must contain exactly its whitelisted files",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total_uncompressed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| invalid_owned(error.to_string()))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| invalid("direct package archive entry name is not UTF-8"))?;
        if name.contains('\\')
            || !entry.is_file()
            || entry.external_attributes() & 0x0400 != 0
            || entry.enclosed_name().is_none()
            || !expected.contains(name)
            || !seen.insert(name.to_owned())
        {
            return Err(invalid(
                "package archive contains an unsafe or unexpected entry",
            ));
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(invalid(
                "package archive uses an unsupported compression method",
            ));
        }
        // ZIP creator OS may be MS-DOS even when the external mode encodes a
        // symlink. Inspect the raw mode, not unix_mode(), which omits that case.
        let file_type = (entry.external_attributes() >> 16) & 0o170000;
        if file_type != 0 && file_type != 0o100000 {
            return Err(invalid("package archive contains a non-regular file"));
        }
        let declared_size = entry.size();
        if declared_size > DIRECT_ARCHIVE_MAX_ENTRY_BYTES
            || entry.compressed_size() > DIRECT_ARCHIVE_MAX_COMPRESSED_BYTES
        {
            return Err(invalid("package archive entry exceeds size limit"));
        }
        total_uncompressed = total_uncompressed
            .checked_add(declared_size)
            .ok_or_else(|| invalid("direct package uncompressed size overflow"))?;
        if total_uncompressed > DIRECT_ARCHIVE_MAX_TOTAL_BYTES {
            return Err(invalid(
                "package archive exceeds total uncompressed size limit",
            ));
        }
        let mut actual_size = 0_u64;
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            actual_size = actual_size
                .checked_add(count as u64)
                .ok_or_else(|| invalid("direct package entry size overflow"))?;
            if actual_size > DIRECT_ARCHIVE_MAX_ENTRY_BYTES || actual_size > declared_size {
                return Err(invalid("package entry exceeds its declared size"));
            }
        }
        if actual_size != declared_size {
            return Err(invalid("package entry size does not match its declaration"));
        }
    }
    if seen != expected {
        return Err(invalid("package archive is missing a required file"));
    }
    Ok(())
}

struct LocalArchiveClient {
    file: Arc<Mutex<File>>,
    url: String,
}

struct LocalArchiveResponse {
    file: File,
    headers: HeaderMap,
}

impl HttpClient for LocalArchiveClient {
    fn get(
        &self,
        url: &str,
        _headers: &HeaderMap,
        _timeout: Option<Duration>,
    ) -> self_update::Result<Box<dyn HttpResponse>> {
        if url != self.url {
            return Err(self_update::Error::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected local archive URL",
            )));
        }
        let mut file = self
            .file
            .lock()
            .map_err(|_| self_update::Error::from(io::Error::other("local archive lock poisoned")))?
            .try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Box::new(LocalArchiveResponse {
            file,
            headers: HeaderMap::new(),
        }))
    }
}

impl HttpResponse for LocalArchiveResponse {
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn body(self: Box<Self>) -> Box<dyn Read> {
        Box::new(self.file)
    }
}

fn required_string<'a>(object: &'a Map<String, Value>, name: &str) -> io::Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_owned(format!("install.json must contain non-empty {name}")))
}

fn validate_update_uri(value: &str, label: &str) -> io::Result<Uri> {
    // `http::Uri` deliberately does not retain URI fragments, so reject them before parsing.
    if value.contains('#') {
        return Err(invalid_owned(format!(
            "{label} must not contain a fragment"
        )));
    }
    let uri = value
        .parse::<Uri>()
        .map_err(|error| invalid_owned(format!("{label} is not a valid absolute URI: {error}")))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| invalid_owned(format!("{label} must be absolute")))?;
    let authority = uri
        .authority()
        .ok_or_else(|| invalid_owned(format!("{label} must contain an authority")))?;
    if authority.as_str().contains('@') {
        return Err(invalid_owned(format!("{label} must not contain userinfo")));
    }
    if authority.host().is_empty() {
        return Err(invalid_owned(format!("{label} must contain a host")));
    }
    if uri
        .path_and_query()
        .and_then(|path_and_query| path_and_query.query())
        .is_some()
    {
        return Err(invalid_owned(format!("{label} must not contain a query")));
    }

    let allowed = scheme.eq_ignore_ascii_case("https")
        || (scheme.eq_ignore_ascii_case("http")
            && authority.host() == "127.0.0.1"
            && authority.port_u16().is_some());
    if !allowed {
        return Err(invalid_owned(format!(
            "{label} must use HTTPS or explicit-port HTTP loopback"
        )));
    }
    Ok(uri)
}

#[derive(Debug, Clone)]
/// Exact runtime bundle selected by an archive digest to install.
struct ExactBundleUpdateRequest {
    /// Package semver used as the exact self_update release tag.
    pub package_version: String,
    /// Package and archive digest identity used by `self_update`.
    pub release_id: String,
    /// Rust target triple whose release archive is being installed.
    pub target: String,
    /// Exact HTTPS archive URL or internal URL for a staged archive.
    pub archive_url: String,
    /// Exact archive file name used for asset matching.
    pub archive_name: String,
    /// Expected SHA-256 of the exact package archive.
    pub archive_sha256: Sha256Digest,
    /// Immutable runtime subtree inside the release archive.
    pub bundle_path_in_archive: String,
    /// Installed immutable runtime directory to replace.
    pub bundle_install_path: PathBuf,
    /// Executable stem used by self_update replacement bookkeeping.
    pub binary_name: String,
    /// Relative files that must exist in the staged runtime before publication.
    pub required_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of one exact runtime package update attempt.
enum ExactBundleUpdateOutcome {
    Updated { release_id: String },
}

#[derive(Clone)]
struct ExactReleaseSource {
    release: Release,
}

impl ReleaseSource for ExactReleaseSource {
    fn get_releases(&self) -> self_update::Result<Vec<Release>> {
        Ok(vec![self.release.clone()])
    }
}

fn install_exact_bundle_unlocked_with_local_file(
    request: &ExactBundleUpdateRequest,
    local_archive: Option<File>,
) -> io::Result<ExactBundleUpdateOutcome> {
    validate_request(request)?;
    let asset = ReleaseAsset::new(&request.archive_name, &request.archive_url)
        .with_digest(format!("sha256:{}", request.archive_sha256));
    let release = Release::builder()
        .version(&request.package_version)
        .name(&request.release_id)
        .asset(asset)
        .build()
        .map_err(update_error)?;
    let source = ExactReleaseSource { release };
    let required_files = Arc::new(request.required_files.clone());

    let mut builder = Update::configure();
    builder
        .source(source)
        .bin_name(&request.binary_name)
        .current_version(&request.package_version)
        // Explicitly select this package version so self_update cannot substitute another tag.
        .release_tag(&request.package_version)
        .target(&request.target)
        .asset_identifier(&request.archive_name)
        .bundle_path_in_archive(&request.bundle_path_in_archive)
        .bundle_install_path(&request.bundle_install_path)
        .verify_checksum(Checksum::Sha256(request.archive_sha256.to_string()))
        .check_install_path_writable(true)
        .unattended()
        .verify_binary(move |staged_root| {
            verify_required_runtime_files(staged_root, &required_files)
                .map_err(self_update::Error::verification_rejected)
        });
    if let Some(file) = local_archive {
        let client = LocalArchiveClient {
            file: Arc::new(Mutex::new(file)),
            url: request.archive_url.clone(),
        };
        builder.http_client(Arc::new(client));
    }

    let updater = builder.build().map_err(update_error)?;
    match updater.update_extended().map_err(update_error)? {
        ReleaseStatus::Updated(release) => {
            if release.name() != request.release_id {
                return Err(io::Error::other(format!(
                    "self_update installed unexpected release identity {:?}",
                    release.name()
                )));
            }
            Ok(ExactBundleUpdateOutcome::Updated {
                release_id: request.release_id.clone(),
            })
        }
        ReleaseStatus::UpToDate => Err(io::Error::other(
            "explicit exact runtime update unexpectedly resolved as up to date",
        )),
        _ => Err(io::Error::other(
            "self_update returned an unsupported release status",
        )),
    }
}

fn verify_required_runtime_files(
    staged_root: &Path,
    required_files: &[PathBuf],
) -> Result<(), String> {
    for relative in required_files {
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(format!(
                "invalid required runtime path {}",
                relative.display()
            ));
        }
        if !staged_root.join(relative).is_file() {
            return Err(format!("staged runtime is missing {}", relative.display()));
        }
    }
    if staged_root.join("onec-ops.exe").exists() {
        return Err("staged runtime contains retired onec-ops.exe".to_owned());
    }
    Ok(())
}

fn validate_request(request: &ExactBundleUpdateRequest) -> io::Result<()> {
    if let Some(identity) = request.release_id.strip_prefix("direct:") {
        let expected_prefix = format!("{}:", request.package_version);
        let Some(content_hash) = identity.strip_prefix(&expected_prefix) else {
            return Err(invalid(
                "direct archive identity is not bound to package_version",
            ));
        };
        Sha256Digest::from_str(content_hash)
            .map_err(|_| invalid("direct archive identity is not SHA-256"))?;
    } else {
        let expected_prefix = format!("{}-sha256-", request.package_version);
        let Some(content_hash) = request.release_id.strip_prefix(&expected_prefix) else {
            return Err(invalid("release_id is not bound to package_version"));
        };
        Sha256Digest::from_str(content_hash)
            .map_err(|_| invalid("release_id content hash is not SHA-256"))?;
    }
    if let Some(digest) = request.archive_url.strip_prefix(LOCAL_ARCHIVE_URL_PREFIX) {
        let expected_identity = format!("direct:{}:{digest}", request.package_version);
        if request.release_id != expected_identity {
            return Err(invalid(
                "local archive URL is not bound to the selected digest",
            ));
        }
        Sha256Digest::from_str(digest)
            .map_err(|_| invalid("local archive URL digest is not SHA-256"))?;
    } else {
        validate_update_uri(&request.archive_url, "archive URL")?;
    }
    if request.archive_name.is_empty()
        || request.archive_name.contains(['/', '\\'])
        || !request.archive_name.ends_with(".zip")
    {
        return Err(invalid("archive name must be one ZIP file name"));
    }
    if request.bundle_path_in_archive.is_empty()
        || request.bundle_path_in_archive.starts_with(['/', '\\'])
        || request.bundle_path_in_archive.contains("..")
    {
        return Err(invalid(
            "bundle path in archive is not a confined relative path",
        ));
    }
    if request.required_files.is_empty() {
        return Err(invalid("required runtime file set is empty"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn update_error(error: self_update::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::path::Path;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;

    fn make_archive(root: &Path, package: &str, marker: &str) -> (PathBuf, String) {
        let archive = root.join("onec-toolkit-x86_64-pc-windows-msvc.zip");
        let file = std::fs::File::create(&archive).expect("archive");
        let mut zip = zip::ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in [
            ("onec-agent.exe", format!("agent-{marker}")),
            ("onec.exe", format!("controller-{marker}")),
            ("Run-OnecAgent.ps1", format!("runner-{marker}")),
            ("Update-OnecToolkit.ps1", format!("updater-{marker}")),
            (
                "onec-toolkit-update.cmd",
                format!("update-command-{marker}"),
            ),
        ] {
            zip.start_file(format!("{package}/{name}"), options)
                .expect("start file");
            zip.write_all(body.as_bytes()).expect("zip body");
        }
        zip.finish().expect("finish zip");
        let bytes = std::fs::read(&archive).expect("archive bytes");
        (archive, format!("{:x}", Sha256::digest(bytes)))
    }

    fn make_direct_archive_with_entries(
        root: &Path,
        entries: &[(&str, &[u8], zip::write::FileOptions<'_, '_, ()>)],
    ) -> (PathBuf, String) {
        let archive = root.join("direct-validation.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).expect("archive"));
        for (name, body, options) in entries {
            zip.start_file(*name, *options).expect("start entry");
            zip.write_all(body).expect("write entry");
        }
        zip.finish().expect("finish archive");
        let bytes = std::fs::read(&archive).expect("archive bytes");
        (archive, format!("{:x}", Sha256::digest(bytes)))
    }

    fn direct_request(
        root: &TempDir,
        archive_url: String,
        archive_sha256: String,
    ) -> DirectPackageUpdateRequest {
        DirectPackageUpdateRequest {
            root: root.path().to_path_buf(),
            archive_url: Some(archive_url),
            archive_file: None,
            archive_sha256,
            package_version: "1.2.3".to_owned(),
            target: "x86_64-pc-windows-msvc".to_owned(),
        }
    }

    fn make_agent_archive(
        root: &Path,
        entries: &[(&str, &[u8], zip::write::SimpleFileOptions)],
    ) -> (PathBuf, String) {
        let archive_path = root.join("agent-package.zip");
        let mut archive = zip::ZipWriter::new(File::create(&archive_path).expect("archive"));
        for (name, body, options) in entries {
            archive.start_file(*name, *options).expect("entry");
            archive.write_all(body).expect("entry bytes");
        }
        archive.finish().expect("finish archive");
        let bytes = std::fs::read(&archive_path).expect("archive bytes");
        (archive_path, format!("{:x}", Sha256::digest(bytes)))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn current_agent_target() -> &'static str {
        "x86_64-unknown-linux-gnu"
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn current_agent_target() -> &'static str {
        "x86_64-pc-windows-msvc"
    }

    #[cfg(all(target_os = "windows", target_arch = "x86"))]
    fn current_agent_target() -> &'static str {
        "i686-win7-windows-msvc"
    }

    fn mismatched_agent_target() -> &'static str {
        if current_agent_target().contains("windows") {
            "x86_64-unknown-linux-gnu"
        } else {
            "x86_64-pc-windows-msvc"
        }
    }

    fn host_agent_archive(root: &Path) -> (PathBuf, String) {
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let package = format!("hostlink-agent-{}", current_agent_target());
        #[cfg(target_os = "windows")]
        let entries = [
            (
                format!("{package}/hostlink-agent.exe"),
                b"hostlink-agent-v1".as_slice(),
                options,
            ),
            (
                format!("{package}/Install-HostLink-Agent.ps1"),
                include_bytes!("../assets/Install-HostLink-Agent.ps1").as_slice(),
                options,
            ),
            (
                format!("{package}/Run-HostLink-Agent.ps1"),
                include_bytes!("../assets/Run-HostLink-Agent.ps1").as_slice(),
                options,
            ),
            (
                format!("{package}/Update-HostLink-Agent.ps1"),
                include_bytes!("../assets/Update-HostLink-Agent.ps1").as_slice(),
                options,
            ),
        ];
        #[cfg(target_os = "linux")]
        let entries = [(
            format!("{package}/hostlink-agent"),
            b"hostlink-agent-v1".as_slice(),
            options,
        )];
        let owned = entries
            .iter()
            .map(|(name, body, options)| (name.as_str(), *body, *options))
            .collect::<Vec<_>>();
        make_agent_archive(root, &owned)
    }

    fn host_agent_executable(root: &Path) -> PathBuf {
        root.join("hostlink-agent/bin")
            .join(if current_agent_target().contains("windows") {
                "hostlink-agent.exe"
            } else {
                "hostlink-agent"
            })
    }

    fn agent_request(root: &TempDir, archive: &Path, digest: String) -> AgentPackageUpdateRequest {
        AgentPackageUpdateRequest {
            root: root.path().to_path_buf(),
            archive_url: None,
            archive_file: Some(archive.to_path_buf()),
            archive_sha256: digest,
            package_version: "1.2.3".to_owned(),
            target: current_agent_target().to_owned(),
        }
    }

    #[test]
    fn agent_only_package_installs_idempotently_and_preserves_legacy_files() {
        let root = TempDir::new().expect("root");
        let (archive, digest) = host_agent_archive(root.path());
        std::fs::create_dir_all(root.path().join("bin")).expect("legacy bin");
        std::fs::write(root.path().join("bin/onec-agent.exe"), b"legacy agent")
            .expect("legacy binary");
        std::fs::write(root.path().join("agent.json"), b"legacy config").expect("legacy config");
        let request = agent_request(&root, &archive, digest.clone());
        assert_eq!(
            update_agent_package(&request).expect("install"),
            RuntimeUpdateOutcome::DirectUpdated {
                package_version: "1.2.3".to_owned(),
                archive_sha256: digest.clone()
            }
        );
        assert_eq!(
            std::fs::read(host_agent_executable(root.path())).expect("installed agent"),
            b"hostlink-agent-v1"
        );
        assert_eq!(
            std::fs::read(root.path().join("bin/onec-agent.exe")).expect("legacy binary"),
            b"legacy agent"
        );
        assert_eq!(
            std::fs::read(root.path().join("agent.json")).expect("legacy config"),
            b"legacy config"
        );
        assert_eq!(
            update_agent_package(&request).expect("idempotent update"),
            RuntimeUpdateOutcome::DirectUpToDate {
                package_version: "1.2.3".to_owned(),
                archive_sha256: digest
            }
        );
    }

    #[test]
    fn agent_only_package_rejects_digest_inventory_target_and_installed_file_mismatches() {
        let root = TempDir::new().expect("root");
        let (archive, digest) = host_agent_archive(root.path());
        let mut wrong_digest = agent_request(&root, &archive, "0".repeat(64));
        assert!(update_agent_package(&wrong_digest).is_err());
        wrong_digest.archive_sha256 = digest.clone();
        wrong_digest.target = mismatched_agent_target().to_owned();
        assert!(update_agent_package(&wrong_digest).is_err());

        let request = agent_request(&root, &archive, digest);
        update_agent_package(&request).expect("initial install");
        let executable = host_agent_executable(root.path());
        std::fs::write(&executable, b"tampered").expect("tamper executable");
        assert!(
            update_agent_package(&request)
                .unwrap_err()
                .to_string()
                .contains("do not match")
        );
        std::fs::remove_file(&executable).expect("remove executable");
        assert!(update_agent_package(&request).is_err());
    }

    #[test]
    fn agent_only_package_rejects_cross_os_target_without_changing_installed_state() {
        let root = TempDir::new().expect("root");
        let (archive, digest) = host_agent_archive(root.path());
        let request = agent_request(&root, &archive, digest);
        update_agent_package(&request).expect("initial install");
        let metadata_path = root.path().join("hostlink-agent/install.json");
        let before_metadata = std::fs::read(&metadata_path).expect("metadata");
        let executable_path = host_agent_executable(root.path());
        let before_executable = std::fs::read(&executable_path).expect("installed executable");

        let mut mismatched = request;
        mismatched.target = mismatched_agent_target().to_owned();
        let error = update_agent_package(&mismatched).expect_err("cross-OS target");
        assert!(
            error
                .to_string()
                .contains("does not match this Agent runtime")
        );
        assert_eq!(
            std::fs::read(metadata_path).expect("unchanged metadata"),
            before_metadata
        );
        assert_eq!(
            std::fs::read(executable_path).expect("unchanged executable"),
            before_executable
        );
    }

    #[test]
    fn agent_only_archive_rejects_extra_onec_traversal_and_symlink_members() {
        let root = TempDir::new().expect("root");
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let (extra, _) = make_agent_archive(
            root.path(),
            &[
                (
                    "hostlink-agent-x86_64-unknown-linux-gnu/hostlink-agent",
                    b"agent",
                    options,
                ),
                (
                    "hostlink-agent-x86_64-unknown-linux-gnu/onec.exe",
                    b"controller",
                    options,
                ),
            ],
        );
        let mut file = File::open(extra).expect("extra archive");
        assert!(validate_agent_archive(&mut file, "x86_64-unknown-linux-gnu").is_err());

        let (traversal, _) = make_agent_archive(
            root.path(),
            &[(
                "hostlink-agent-x86_64-unknown-linux-gnu/../outside",
                b"bad",
                options,
            )],
        );
        let mut file = File::open(traversal).expect("traversal archive");
        assert!(validate_agent_archive(&mut file, "x86_64-unknown-linux-gnu").is_err());

        let (symlink, _) = make_agent_archive(
            root.path(),
            &[(
                "hostlink-agent-x86_64-unknown-linux-gnu/hostlink-agent",
                b"target",
                options,
            )],
        );
        let mut bytes = std::fs::read(&symlink).expect("symlink archive bytes");
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central file header");
        // Mark the producer as MS-DOS while retaining Unix symlink attributes:
        // unix_mode() then returns None, but the unsafe mode must be rejected.
        bytes[central + 5] = 0;
        bytes[central + 38..central + 42].copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
        std::fs::write(&symlink, bytes).expect("mark ZIP member as symlink");
        let mut file = File::open(symlink).expect("symlink archive");
        assert!(validate_agent_archive(&mut file, "x86_64-unknown-linux-gnu").is_err());
    }

    #[test]
    fn agent_only_install_rejects_target_conflict_and_unsafe_root_or_archive_scope() {
        let root = TempDir::new().expect("root");
        let (archive, digest) = host_agent_archive(root.path());
        std::fs::create_dir_all(root.path().join("hostlink-agent")).expect("install root");
        std::fs::write(
            root.path().join("hostlink-agent/install.json"),
            format!(r#"{{"target":"{}"}}"#, mismatched_agent_target()).as_bytes(),
        )
        .expect("metadata");
        let request = agent_request(&root, &archive, digest);
        assert!(
            update_agent_package(&request)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut request = request;
        request.archive_file = Some(root.path().parent().expect("parent").join("outside.zip"));
        assert!(validate_agent_package(&request).is_ok());
        assert!(
            open_scoped_archive(root.path(), request.archive_file.as_deref().unwrap()).is_err()
        );
        request.target = "../../linux".to_owned();
        assert!(validate_agent_package(&request).is_err());
        request.target = current_agent_target().to_owned();
        request.archive_file = None;
        request.archive_url = Some("file:///tmp/package.zip".to_owned());
        assert!(validate_agent_package(&request).is_err());
    }

    #[test]
    fn agent_only_update_defers_when_a_durable_job_is_active() {
        let root = TempDir::new().expect("root");
        let (archive, digest) = host_agent_archive(root.path());
        let job_dir = root.path().join("jobs/job-active");
        std::fs::create_dir_all(&job_dir).expect("job directory");
        std::fs::write(
            job_dir.join("state-000000.json"),
            br#"{"version":1,"job":{"job_id":"job-active","state":"running","created_unix_ms":1},"process_identities":{"version":0}}"#,
        )
        .expect("active job state");
        assert_eq!(
            update_agent_package(&agent_request(&root, &archive, digest)).expect("deferred update"),
            RuntimeUpdateOutcome::DeferredActiveJobs {
                job_ids: vec!["job-active".to_owned()]
            }
        );
        assert!(!host_agent_executable(root.path()).exists());
    }

    #[cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn agent_only_update_rejects_symlinked_install_root() {
        let parent = TempDir::new().expect("parent");
        let actual = TempDir::new().expect("actual root");
        let root_link = parent.path().join("root-link");
        std::os::unix::fs::symlink(actual.path(), &root_link).expect("root symlink");
        let archive = actual.path().join("package.zip");
        let options = SimpleFileOptions::default();
        let mut zip = zip::ZipWriter::new(File::create(&archive).expect("archive"));
        zip.start_file(
            format!("hostlink-agent-{}/hostlink-agent", current_agent_target()).as_str(),
            options,
        )
        .expect("entry");
        zip.write_all(b"agent").expect("body");
        zip.finish().expect("finish");
        let bytes = std::fs::read(&archive).expect("archive bytes");
        let request = AgentPackageUpdateRequest {
            root: root_link,
            archive_url: None,
            archive_file: Some(archive),
            archive_sha256: format!("{:x}", Sha256::digest(bytes)),
            package_version: "1.2.3".to_owned(),
            target: current_agent_target().to_owned(),
        };
        assert!(update_agent_package(&request).is_err());
        assert!(!actual.path().join("update.lock").exists());
    }

    #[test]
    fn windows_agent_inventory_matches_the_hostlink_packager_names() {
        let root = TempDir::new().expect("root");
        let options = SimpleFileOptions::default();
        let entries = [
            (
                "hostlink-agent-x86_64-win7-windows-msvc/hostlink-agent.exe",
                b"exe".as_slice(),
                options,
            ),
            (
                "hostlink-agent-x86_64-win7-windows-msvc/Install-HostLink-Agent.ps1",
                b"install".as_slice(),
                options,
            ),
            (
                "hostlink-agent-x86_64-win7-windows-msvc/Run-HostLink-Agent.ps1",
                b"run".as_slice(),
                options,
            ),
            (
                "hostlink-agent-x86_64-win7-windows-msvc/Update-HostLink-Agent.ps1",
                b"update".as_slice(),
                options,
            ),
        ];
        let (archive, _) = make_agent_archive(root.path(), &entries);
        let mut file = File::open(archive).expect("archive file");
        validate_agent_archive(&mut file, "x86_64-win7-windows-msvc")
            .expect("exact Windows inventory");
    }

    fn write_direct_install_metadata(root: &Path, extra: Value) {
        let mut metadata = serde_json::json!({
            "version": 2,
            "target": "x86_64-pc-windows-msvc",
            "installed_version": "1.0.0",
            "persistence_mode": "user-session"
        });
        metadata
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("extra object").clone());
        std::fs::write(
            root.join("install.json"),
            serde_json::to_vec(&metadata).expect("metadata"),
        )
        .expect("write metadata");
    }

    fn write_direct_runtime(root: &Path) -> Value {
        let runtime = root.join("bin");
        std::fs::create_dir_all(&runtime).expect("runtime");
        for file in required_runtime_files() {
            std::fs::write(runtime.join(file), b"installed runtime bytes").expect("runtime file");
        }
        runtime_file_identities(root, &required_runtime_files()).expect("runtime identities")
    }

    #[test]
    fn direct_package_uses_exact_archive_version_target_and_confined_bundle_scope() {
        let root = TempDir::new().expect("root");
        let request = direct_request(
            &root,
            "https://packages.example.test/releases/toolkit.zip".to_owned(),
            "a".repeat(64),
        );
        validate_direct_package(&request).expect("valid direct request");
        let exact = direct_bundle_request(
            &request,
            Sha256Digest::from_str(&request.archive_sha256).expect("digest"),
            request.archive_url.clone().expect("URL source"),
        );

        assert_eq!(
            exact.archive_url,
            request.archive_url.clone().expect("URL source")
        );
        assert_eq!(exact.package_version, "1.2.3");
        assert_eq!(exact.target, "x86_64-pc-windows-msvc");
        assert_eq!(
            exact.archive_name,
            "onec-toolkit-x86_64-pc-windows-msvc.zip"
        );
        assert_eq!(
            exact.bundle_path_in_archive,
            "onec-toolkit-x86_64-pc-windows-msvc"
        );
        assert_eq!(exact.bundle_install_path, root.path().join("bin"));
        assert_eq!(exact.required_files, required_runtime_files());
        validate_request(&exact).expect("exact installer request");
    }

    #[test]
    fn direct_package_rejects_unsupported_target_bad_url_scope_and_version() {
        let root = TempDir::new().expect("root");
        let mut request = direct_request(
            &root,
            "https://packages.example.test/releases/toolkit.zip".to_owned(),
            "a".repeat(64),
        );
        request.target = "x86_64-unknown-linux-gnu".to_owned();
        assert!(validate_direct_package(&request).is_err());

        request.target = "x86_64-pc-windows-msvc".to_owned();
        request.archive_url =
            Some("https://packages.example.test/releases/../outside.zip".to_owned());
        assert!(validate_direct_package(&request).is_err());
        request.archive_url =
            Some("https://packages.example.test/releases/toolkit.zip?latest=1".to_owned());
        assert!(validate_direct_package(&request).is_err());
        request.archive_url =
            Some("http://packages.example.test:443/releases/toolkit.zip".to_owned());
        assert!(validate_direct_package(&request).is_err());

        request.archive_url = Some("https://packages.example.test/releases/toolkit.zip".to_owned());
        request.package_version = "../1.2.3".to_owned();
        assert!(validate_direct_package(&request).is_err());
        request.package_version = "01.2.3".to_owned();
        assert!(validate_direct_package(&request).is_err());
        request.package_version = "1.2.3-alpha.01".to_owned();
        assert!(validate_direct_package(&request).is_err());
        request.package_version = "1.2.3-alpha+build.7".to_owned();
        validate_direct_package(&request).expect("valid semver prerelease and build metadata");
    }

    #[test]
    fn direct_package_digest_mismatch_preserves_installed_runtime() {
        let root = TempDir::new().expect("root");
        let package = "onec-toolkit-x86_64-pc-windows-msvc";
        let (archive, sha) = make_archive(root.path(), package, "new");
        let mut request = direct_request(&root, String::new(), sha.clone());
        request.archive_url = None;
        request.archive_file = Some(archive.clone());
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let runtime = root.path().join("bin");
        std::fs::create_dir_all(&runtime).expect("runtime");
        std::fs::write(runtime.join("onec-agent.exe"), b"old-agent").expect("old agent");

        let digest = Sha256Digest::from_str(&sha).expect("digest");
        let mut file = open_scoped_archive(root.path(), &archive).expect("scoped archive");
        verify_open_archive_digest(&mut file, &digest).expect("initial digest");
        // Mutate the same opened file after the precheck; Update must reject the streamed bytes.
        std::fs::write(&archive, b"changed after precheck").expect("mutate staged archive");
        let exact =
            direct_bundle_request(&request, digest, format!("{LOCAL_ARCHIVE_URL_PREFIX}{sha}"));

        let error = install_exact_bundle_unlocked_with_local_file(&exact, Some(file))
            .expect_err("streamed digest mismatch");
        assert!(
            error.to_string().to_lowercase().contains("checksum"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(runtime.join("onec-agent.exe")).expect("old agent"),
            b"old-agent"
        );

        let error = update_direct_package(&request).expect_err("changed staged ZIP digest");
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert_eq!(
            std::fs::read(runtime.join("onec-agent.exe")).expect("old agent after ZIP rejection"),
            b"old-agent"
        );
    }

    #[test]
    fn direct_package_installs_root_scoped_local_zip_and_publishes_digest_metadata() {
        let root = TempDir::new().expect("root");
        let package = "onec-toolkit-x86_64-pc-windows-msvc";
        let (archive, sha) = make_archive(root.path(), package, "local");
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let mut request = direct_request(&root, String::new(), sha.clone());
        request.archive_url = None;
        request.archive_file = Some(archive.clone());
        std::fs::create_dir_all(root.path().join("bin")).expect("bin");
        std::fs::write(root.path().join("bin/onec-agent.exe"), b"old-agent").expect("old agent");

        let outcome = update_direct_package(&request).expect("install local package");
        assert_eq!(
            outcome,
            RuntimeUpdateOutcome::DirectUpdated {
                package_version: "1.2.3".to_owned(),
                archive_sha256: sha.clone(),
            }
        );
        assert_eq!(
            std::fs::read(root.path().join("bin/onec-agent.exe")).expect("new agent"),
            b"agent-local"
        );
        let metadata: Value = serde_json::from_slice(
            &std::fs::read(root.path().join("install.json")).expect("metadata"),
        )
        .expect("metadata JSON");
        assert_eq!(metadata["installed_version"], "1.2.3");
        assert_eq!(metadata["installed_package_sha256"], sha);
        assert!(metadata.get("installed_release_id").is_none());
    }

    #[test]
    fn direct_package_archive_preflight_accepts_exact_five_files_and_rejects_bad_shapes() {
        let root = TempDir::new().expect("root");
        let package = "onec-toolkit-x86_64-pc-windows-msvc";
        let (valid, _) = make_archive(root.path(), package, "valid");
        let mut valid_file = File::open(&valid).expect("open valid archive");
        validate_direct_archive(&mut valid_file, "x86_64-pc-windows-msvc")
            .expect("exact archive accepted");

        let duplicate_bytes = std::fs::read(&valid).expect("valid archive bytes");
        let eocd = duplicate_bytes
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("end of central directory");
        let central_start = u32::from_le_bytes(
            duplicate_bytes[eocd + 16..eocd + 20]
                .try_into()
                .expect("central offset"),
        ) as usize;
        let central_size = u32::from_le_bytes(
            duplicate_bytes[eocd + 12..eocd + 16]
                .try_into()
                .expect("central size"),
        ) as usize;
        let mut central = Vec::with_capacity(central_size);
        let mut offset = central_start;
        let mut first_name = None;
        for index in 0..5 {
            let name_len = u16::from_le_bytes(
                duplicate_bytes[offset + 28..offset + 30]
                    .try_into()
                    .expect("filename length"),
            ) as usize;
            let extra_len = u16::from_le_bytes(
                duplicate_bytes[offset + 30..offset + 32]
                    .try_into()
                    .expect("extra length"),
            ) as usize;
            let comment_len = u16::from_le_bytes(
                duplicate_bytes[offset + 32..offset + 34]
                    .try_into()
                    .expect("comment length"),
            ) as usize;
            let record_len = 46 + name_len + extra_len + comment_len;
            let name_start = offset + 46;
            let name = duplicate_bytes[name_start..name_start + name_len].to_vec();
            if index == 0 {
                first_name = Some(name.clone());
            }
            if index == 1 {
                let first_name = first_name.as_ref().expect("first name");
                let record_start = central.len();
                central.extend_from_slice(&duplicate_bytes[offset..offset + 46]);
                central[record_start + 28..record_start + 30]
                    .copy_from_slice(&(first_name.len() as u16).to_le_bytes());
                central.extend_from_slice(first_name);
                central.extend_from_slice(
                    &duplicate_bytes[name_start + name_len..offset + record_len],
                );
            } else {
                central.extend_from_slice(&duplicate_bytes[offset..offset + record_len]);
            }
            offset += record_len;
        }
        let mut duplicate_archive = duplicate_bytes[..central_start].to_vec();
        duplicate_archive.extend_from_slice(&central);
        duplicate_archive.extend_from_slice(&duplicate_bytes[eocd..]);
        let new_eocd = central_start + central.len();
        duplicate_archive[new_eocd + 12..new_eocd + 16]
            .copy_from_slice(&(central.len() as u32).to_le_bytes());
        let duplicate_path = root.path().join("duplicate.zip");
        std::fs::write(&duplicate_path, duplicate_archive).expect("write duplicate archive");
        let mut file = File::open(duplicate_path).expect("duplicate archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let required = [
            "onec-agent.exe",
            "onec.exe",
            "Run-OnecAgent.ps1",
            "Update-OnecToolkit.ps1",
            "onec-toolkit-update.cmd",
        ];
        let mut entries = required
            .iter()
            .map(|name| (format!("{package}/{name}"), b"bytes".as_slice(), options))
            .collect::<Vec<_>>();
        entries[0].0 = format!("{package}/../outside.exe");
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (traversal, _) = make_direct_archive_with_entries(root.path(), &owned);
        let mut file = File::open(traversal).expect("traversal archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let mut entries = required
            .iter()
            .map(|name| (format!("{package}/{name}"), b"bytes".as_slice(), options))
            .collect::<Vec<_>>();
        entries.pop();
        entries.push((format!("{package}/extra.dll"), b"extra".as_slice(), options));
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (unknown, _) = make_direct_archive_with_entries(root.path(), &owned);
        let mut file = File::open(unknown).expect("unknown archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let entries = required
            .iter()
            .take(4)
            .map(|name| (format!("{package}/{name}"), b"bytes".as_slice(), options))
            .collect::<Vec<_>>();
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (missing, _) = make_direct_archive_with_entries(root.path(), &owned);
        let mut file = File::open(missing).expect("missing-file archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let symlink_options = options
            .external_attributes(0o120777 << 16)
            .system(zip::System::Unix);
        let entries = required
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    format!("{package}/{name}"),
                    b"bytes".as_slice(),
                    if index == 0 { symlink_options } else { options },
                )
            })
            .collect::<Vec<_>>();
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (symlink, _) = make_direct_archive_with_entries(root.path(), &owned);
        let mut file = File::open(symlink).expect("symlink archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let (oversized, _) = make_archive(root.path(), package, "oversized");
        let mut bytes = std::fs::read(&oversized).expect("oversized archive bytes");
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central directory entry");
        let declared_size = (DIRECT_ARCHIVE_MAX_ENTRY_BYTES + 1) as u32;
        bytes[central + 24..central + 28].copy_from_slice(&declared_size.to_le_bytes());
        std::fs::write(&oversized, bytes).expect("write oversized declaration");
        let mut file = File::open(oversized).expect("oversized declaration archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());

        let stored =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let entries = required
            .iter()
            .map(|name| (format!("{package}/{name}"), b"bytes".as_slice(), stored))
            .collect::<Vec<_>>();
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (corrupt, _) = make_direct_archive_with_entries(root.path(), &owned);
        let mut bytes = std::fs::read(&corrupt).expect("corrupt archive bytes");
        let body = bytes
            .windows(5)
            .position(|window| window == b"bytes")
            .expect("stored file body");
        bytes[body] ^= 1;
        std::fs::write(&corrupt, bytes).expect("write corrupt body");
        let mut file = File::open(corrupt).expect("corrupt archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());
    }

    #[test]
    fn rejected_direct_archive_does_not_replace_runtime_or_leave_staging_files() {
        let root = TempDir::new().expect("root");
        let package = "onec-toolkit-x86_64-pc-windows-msvc";
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let required = [
            "onec-agent.exe",
            "onec.exe",
            "Run-OnecAgent.ps1",
            "Update-OnecToolkit.ps1",
            "onec-toolkit-update.cmd",
        ];
        let mut entries = required
            .iter()
            .map(|name| {
                (
                    format!("{package}/{name}"),
                    b"new bytes".as_slice(),
                    options,
                )
            })
            .collect::<Vec<_>>();
        entries[0].0 = format!("{package}/../outside.exe");
        let owned = entries
            .iter()
            .map(|(name, bytes, options)| (name.as_str(), *bytes, *options))
            .collect::<Vec<_>>();
        let (archive, digest) = make_direct_archive_with_entries(root.path(), &owned);
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let identities = write_direct_runtime(root.path());
        let mut request = direct_request(&root, String::new(), digest);
        request.archive_url = None;
        request.archive_file = Some(archive);

        assert!(update_direct_package(&request).is_err());
        assert_eq!(
            runtime_file_identities(root.path(), &required_runtime_files()).unwrap(),
            identities
        );
        let files = std::fs::read_dir(root.path())
            .expect("root listing")
            .map(|entry| entry.expect("root entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 4, "no staging output should remain: {files:?}");
    }

    #[test]
    fn direct_package_rejects_archive_with_oversized_real_inflation() {
        let root = TempDir::new().expect("root");
        let package = "onec-toolkit-x86_64-pc-windows-msvc";
        let path = root.path().join("inflated.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).expect("archive"));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let required = [
            "onec-agent.exe",
            "onec.exe",
            "Run-OnecAgent.ps1",
            "Update-OnecToolkit.ps1",
            "onec-toolkit-update.cmd",
        ];
        for (index, name) in required.iter().enumerate() {
            zip.start_file(format!("{package}/{name}"), options)
                .expect("start entry");
            if index == 0 {
                let mut inflation = std::io::repeat(0).take(DIRECT_ARCHIVE_MAX_ENTRY_BYTES + 1);
                std::io::copy(&mut inflation, &mut zip).expect("write oversized inflation");
            } else {
                zip.write_all(b"small").expect("write small entry");
            }
        }
        zip.finish().expect("finish archive");
        let mut file = File::open(path).expect("inflated archive");
        assert!(validate_direct_archive(&mut file, "x86_64-pc-windows-msvc").is_err());
    }

    #[test]
    fn direct_package_active_jobs_defer_before_reading_metadata_or_network() {
        let root = TempDir::new().expect("root");
        let jobs = root.path().join("jobs/job-active");
        std::fs::create_dir_all(&jobs).expect("jobs");
        std::fs::write(
            jobs.join("state-000000.json"),
            r#"{"version":1,"job":{"job_id":"job-active","state":"running","worker_pid":null,"process_pid":null,"exit_code":null,"created_unix_ms":1,"started_unix_ms":null,"finished_unix_ms":null,"message":null}}"#,
        )
        .expect("state");
        let request = direct_request(
            &root,
            "https://packages.example.test/toolkit.zip".to_owned(),
            "a".repeat(64),
        );

        assert_eq!(
            update_direct_package(&request).expect("deferred"),
            RuntimeUpdateOutcome::DeferredActiveJobs {
                job_ids: vec!["job-active".to_owned()]
            }
        );
        assert!(!root.path().join("install.json").exists());
    }

    #[test]
    fn direct_package_digest_is_idempotent_without_archive_request() {
        let root = TempDir::new().expect("root");
        let sha = "b".repeat(64);
        let runtime_files = write_direct_runtime(root.path());
        write_direct_install_metadata(
            root.path(),
            serde_json::json!({
                "installed_version": "1.2.3",
                "installed_package_sha256": sha,
                "installed_runtime_files": runtime_files
            }),
        );
        let request = direct_request(
            &root,
            "https://packages.example.test/never-requested.zip".to_owned(),
            sha.clone(),
        );

        assert_eq!(
            update_direct_package(&request).expect("up to date"),
            RuntimeUpdateOutcome::DirectUpToDate {
                package_version: "1.2.3".to_owned(),
                archive_sha256: sha,
            }
        );
    }

    #[test]
    fn installer_fingerprint_is_idempotent_only_for_same_semver_and_verified_files() {
        let root = TempDir::new().expect("root");
        let sha = "b".repeat(64);
        let runtime_files = write_direct_runtime(root.path());
        write_direct_install_metadata(
            root.path(),
            serde_json::json!({
                "installed_version": "0.3.2+src2c30b987d29bb4cf",
                "installed_package_sha256": sha,
                "installed_runtime_files": runtime_files
            }),
        );
        let metadata_before = std::fs::read(root.path().join("install.json")).expect("metadata");
        let runtime_files_before = runtime_file_identities(root.path(), &required_runtime_files())
            .expect("runtime identities before repeat");
        let mut request = direct_request(
            &root,
            "https://packages.example.test/never-requested.zip".to_owned(),
            sha.clone(),
        );
        request.package_version = "0.3.2".to_owned();
        assert_eq!(
            update_direct_package(&request).expect("same exact archive already current"),
            RuntimeUpdateOutcome::DirectUpToDate {
                package_version: "0.3.2".to_owned(),
                archive_sha256: sha,
            }
        );
        assert_eq!(
            runtime_file_identities(root.path(), &required_runtime_files())
                .expect("runtime identities after repeat"),
            runtime_files_before,
            "already-current must not replace the installed bundle"
        );
        assert_eq!(
            std::fs::read(root.path().join("install.json")).expect("metadata after repeat"),
            metadata_before,
            "already-current must not rewrite install metadata"
        );

        request.package_version = "0.3.2-rc.1".to_owned();
        assert!(
            update_direct_package(&request)
                .expect_err("pre-release mismatch must fail")
                .to_string()
                .contains("conflicts")
        );
        request.package_version = "0.3.3".to_owned();
        assert!(
            update_direct_package(&request)
                .expect_err("wrong package version must fail")
                .to_string()
                .contains("conflicts")
        );
    }

    #[test]
    fn direct_package_matching_archive_digest_rejects_missing_installed_runtime_file() {
        let root = TempDir::new().expect("root");
        let sha = "b".repeat(64);
        let runtime_files = write_direct_runtime(root.path());
        std::fs::remove_file(root.path().join("bin/onec-agent.exe")).expect("remove agent");
        write_direct_install_metadata(
            root.path(),
            serde_json::json!({
                "installed_version": "1.2.3",
                "installed_package_sha256": sha,
                "installed_runtime_files": runtime_files
            }),
        );
        let request = direct_request(
            &root,
            "https://packages.example.test/never-requested.zip".to_owned(),
            "b".repeat(64),
        );

        let error = update_direct_package(&request).expect_err("missing installed binary");
        assert!(
            error.to_string().contains("installed runtime file"),
            "{error}"
        );
        assert!(
            error.to_string().contains("run the direct installer"),
            "{error}"
        );
    }

    #[test]
    fn direct_package_matching_archive_digest_rejects_tampered_installed_runtime_file() {
        let root = TempDir::new().expect("root");
        let sha = "b".repeat(64);
        let runtime_files = write_direct_runtime(root.path());
        write_direct_install_metadata(
            root.path(),
            serde_json::json!({
                "installed_version": "1.2.3",
                "installed_package_sha256": sha,
                "installed_runtime_files": runtime_files
            }),
        );
        std::fs::write(
            root.path().join("bin/onec-agent.exe"),
            b"tampered runtime bytes",
        )
        .expect("tamper agent");
        let request = direct_request(
            &root,
            "https://packages.example.test/never-requested.zip".to_owned(),
            "b".repeat(64),
        );

        let error = update_direct_package(&request).expect_err("tampered installed binary");
        assert!(
            error.to_string().contains("do not match install.json"),
            "{error}"
        );
        assert!(
            error.to_string().contains("run the direct installer"),
            "{error}"
        );
    }

    #[test]
    fn direct_package_rejects_install_root_with_a_different_target() {
        let root = TempDir::new().expect("root");
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let mut request = direct_request(
            &root,
            "https://packages.example.test/toolkit.zip".to_owned(),
            "c".repeat(64),
        );
        request.target = "x86_64-win7-windows-msvc".to_owned();

        let error = update_direct_package(&request).expect_err("target mismatch");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("does not match install.json target")
        );
        assert!(!root.path().join("bin").exists());
    }

    #[test]
    fn direct_package_rejects_out_of_root_archive_and_malformed_digest() {
        let root = TempDir::new().expect("root");
        let outside = TempDir::new().expect("outside");
        let archive = outside.path().join("package.zip");
        std::fs::write(&archive, b"not read").expect("outside archive");
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let mut request = direct_request(&root, String::new(), "e".repeat(64));
        request.archive_url = None;
        request.archive_file = Some(root.path().join("../outside/package.zip"));
        let error = update_direct_package(&request).expect_err("parent traversal");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        request.archive_file = Some(archive);

        let error = update_direct_package(&request).expect_err("outside path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("inside the canonical toolkit root")
        );

        let malformed_root = TempDir::new().expect("malformed root");
        let mut malformed =
            direct_request(&malformed_root, String::new(), "not-a-digest".to_owned());
        malformed.archive_url = None;
        malformed.archive_file = Some(malformed_root.path().join("package.zip"));
        let error = update_direct_package(&malformed).expect_err("malformed digest");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!malformed_root.path().join("update.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn direct_package_rejects_symlinked_staged_archive() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().expect("root");
        let outside = TempDir::new().expect("outside");
        let outside_archive = outside.path().join("package.zip");
        std::fs::write(&outside_archive, b"not read through symlink").expect("archive");
        let symlinked_archive = root.path().join("uploaded.zip");
        symlink(&outside_archive, &symlinked_archive).expect("symlink");
        write_direct_install_metadata(root.path(), serde_json::json!({}));
        let mut request = direct_request(&root, String::new(), "f".repeat(64));
        request.archive_url = None;
        request.archive_file = Some(symlinked_archive);

        let error = update_direct_package(&request).expect_err("symlink archive");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("symlinks or reparse points")
                || error
                    .to_string()
                    .contains("inside the canonical toolkit root")
        );
    }

    #[test]
    fn direct_package_digest_cannot_be_relabelled_with_another_version() {
        let root = TempDir::new().expect("root");
        let sha = "d".repeat(64);
        write_direct_install_metadata(
            root.path(),
            serde_json::json!({"installed_package_sha256": sha}),
        );
        let request = direct_request(
            &root,
            "https://packages.example.test/never-requested.zip".to_owned(),
            sha,
        );

        let error = update_direct_package(&request).expect_err("version conflict");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("conflicts with the installed archive digest")
        );
    }
}
