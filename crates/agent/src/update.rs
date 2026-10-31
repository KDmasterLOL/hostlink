//! Update an already installed Agent through upstream self_update.
//! Fresh installation, archive policy and installed-file models live outside
//! this module; there is no second updater or compatibility migration.

use crate::agent_files::validate_user_owned_root;
#[cfg(unix)]
use crate::package::EXECUTABLE_BASE;
#[cfg(test)]
use crate::package::MAX_ARCHIVE_BYTES;
use crate::package::{
    INSTALL_METADATA, InstallMetadata, MAX_MANIFEST_BYTES, PACKAGE_MANIFEST, PackageManifest,
    invalid, read_installed, read_regular, supported_targets, target_matches_runtime,
    validate_contents, validate_installed, validate_sha256,
};
use crate::private_fs::PrivateFileExt;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use reqwest::Url;
use self_update::{
    Checksum, Release, ReleaseAsset, ReleaseSource, ReleaseStatus, backends::custom::Update,
};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Artifact {
    pub(super) url: Url,
    pub(super) sha256: String,
    pub(super) target: String,
    pub(super) version: String,
}

impl Artifact {
    pub fn new(url: &str, sha256: String, target: String, version: String) -> io::Result<Self> {
        Self::parse(url, sha256, target, version, false)
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn loopback(
        url: &str,
        sha256: String,
        target: String,
        version: String,
    ) -> io::Result<Self> {
        Self::parse(url, sha256, target, version, true)
    }

    fn parse(
        value: &str,
        sha256: String,
        target: String,
        version: String,
        fixture_http: bool,
    ) -> io::Result<Self> {
        validate_sha256(&sha256)?;
        semver::Version::parse(&version).map_err(|_| invalid("exact semantic version required"))?;
        if !supported_targets().contains(&target.as_str()) || !target_matches_runtime(&target) {
            return Err(invalid("unsupported Agent target for this runtime"));
        }
        if value.contains(['\\', '%', '@'])
            || value.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(invalid(
                "artifact URL requires a literal path without traversal or credentials",
            ));
        }
        let url = Url::parse(value).map_err(|_| invalid("invalid artifact URL"))?;
        let loopback = fixture_http
            && url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some_and(|port| port != 0);
        if (!loopback && url.scheme() != "https")
            || url.host_str().is_none()
            || url.port() == Some(0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "credential-free HTTPS artifact URL without a fragment required",
            ));
        }
        let name = format!("hostlink-agent-{target}.zip");
        let tagged = format!("v{version}");
        let segments = url
            .path_segments()
            .ok_or_else(|| invalid("invalid artifact URL path"))?
            .collect::<Vec<_>>();
        if segments.last().copied() != Some(name.as_str())
            || !segments
                .iter()
                .any(|part| *part == version || *part == tagged)
        {
            return Err(invalid(
                "artifact URL must name the exact version and target",
            ));
        }
        Ok(Self {
            url,
            sha256,
            target,
            version,
        })
    }
}

impl ReleaseSource for Artifact {
    fn get_releases(&self) -> self_update::Result<Vec<Release>> {
        Ok(vec![
            Release::builder()
                .version(&self.version)
                .asset(ReleaseAsset::new(
                    format!("hostlink-agent-{}.zip", self.target),
                    self.url.as_str(),
                ))
                .build()?,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct AgentUpdateRequest {
    pub install_root: PathBuf,
    pub artifact: Artifact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentUpdateOutcome {
    AlreadyCurrent {
        version: String,
        archive_sha256: String,
    },
    Installed {
        version: String,
        archive_sha256: String,
    },
}

/// Apply one independently pinned URL to a fully stopped Agent.
/// No Agent/service restart is performed. A kill between upstream renames may leave bin absent.
pub fn apply(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    let _locks = acquire(&request.install_root)?;
    let old = read_installed(&request.install_root)?;
    let selected = &request.artifact;
    if old.target != selected.target {
        return Err(invalid(
            "selected Agent target differs from installed target",
        ));
    }
    if old.installed_package_sha256 == selected.sha256 {
        if old.installed_version != selected.version {
            return Err(invalid(
                "installed version conflicts with the selected archive SHA-256",
            ));
        }
        return Ok(AgentUpdateOutcome::AlreadyCurrent {
            version: selected.version.clone(),
            archive_sha256: selected.sha256.clone(),
        });
    }
    publish(request, &old)?;
    Ok(AgentUpdateOutcome::Installed {
        version: selected.version.clone(),
        archive_sha256: selected.sha256.clone(),
    })
}

fn acquire(root: &Path) -> io::Result<(File, File)> {
    if !root.is_absolute() {
        return Err(invalid("Agent install root must be absolute"));
    }
    validate_user_owned_root(root)?;
    let open = |parent: &Path, name: &str| -> io::Result<File> {
        PrivateDir::open(parent)
            .and_then(|dir| {
                dir.open_file_with(
                    name,
                    OpenOptions {
                        access: FileAccess::ReadWrite,
                        creation: FileCreation::OpenOrCreate,
                        ..OpenOptions::default()
                    },
                )
            })
            .map_err(io::Error::other)?
            .try_clone_std()
    };
    let update = open(root, "update.lock")?;
    update
        .try_lock()
        .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?;
    let runner = open(&root.join("jobs"), "runner.lock")?;
    runner.try_lock().map_err(|error| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("stop the running Agent before updating: {error}"),
        )
    })?;
    #[cfg(windows)]
    crate::service::ensure_agent_offline(root)?;
    Ok((update, runner))
}

fn publish(request: &AgentUpdateRequest, old: &InstallMetadata) -> io::Result<()> {
    let artifact = &request.artifact;
    let verified = Arc::new(OnceLock::new());
    let archive_verified = Arc::clone(&verified);
    let selected = artifact.clone();
    let bundle_verified = Arc::clone(&verified);
    let bundle_artifact = artifact.clone();
    let agent = ureq::Agent::config_builder()
        .https_only(artifact.url.scheme() == "https") // HTTP artifacts exist only in unit fixtures.
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();
    let status = Update::configure()
        .source(artifact.clone())
        .release_tag(&artifact.version)
        .current_version(&old.installed_version)
        .target(&artifact.target)
        .bin_name("hostlink-agent")
        .bundle_path_in_archive(format!("hostlink-agent-{}", artifact.target))
        .bundle_install_path(request.install_root.join("bin"))
        .no_confirm(true)
        .show_output(false)
        .retries(0)
        .ureq_agent(agent)
        .verify_checksum(Checksum::Sha256(artifact.sha256.clone()))
        .verify_archive(move |path| {
            let validated = validate_contents(path, &selected.target, &selected.version)?;
            archive_verified
                .set(validated)
                .map_err(|_| invalid("archive hook ran twice"))?;
            Ok(())
        })
        .verify_binary(move |path| {
            let (manifest, bytes) = bundle_verified
                .get()
                .ok_or_else(|| invalid("archive hook did not run"))?;
            prepare_bundle(path, &bundle_artifact, manifest, bytes)?;
            Ok(())
        })
        .build()
        .map_err(io::Error::other)?
        .update_extended()
        .map_err(io::Error::other)?;
    if !matches!(status, ReleaseStatus::Updated(ref release) if release.version() == artifact.version)
    {
        return Err(invalid(
            "self_update did not install the exact pinned release",
        ));
    }
    let installed = read_installed(&request.install_root)?;
    if installed.installed_package_sha256 != artifact.sha256
        || installed.installed_version != artifact.version
    {
        return Err(invalid(
            "published Agent identity differs from the selected artifact",
        ));
    }
    Ok(())
}

fn prepare_bundle(
    path: &Path,
    artifact: &Artifact,
    manifest: &PackageManifest,
    bytes: &[u8],
) -> io::Result<()> {
    if read_regular(&path.join(PACKAGE_MANIFEST))? != bytes {
        return Err(invalid("extracted manifest differs from verified archive"));
    }
    // The published format contains metadata beside the executable, never state/jobs/keys.
    fs::remove_file(path.join(PACKAGE_MANIFEST))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let executable = path.join(EXECUTABLE_BASE);
        let mode = fs::metadata(&executable)?.permissions().mode();
        fs::set_permissions(executable, fs::Permissions::from_mode(mode | 0o100))?;
    }
    let metadata = InstallMetadata {
        format: 2,
        target: artifact.target.clone(),
        installed_version: artifact.version.clone(),
        installed_package_sha256: artifact.sha256.clone(),
        installed_files: manifest.files.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&metadata)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("generated install metadata exceeds its size limit"));
    }
    fs::write(path.join(INSTALL_METADATA), bytes)?;
    validate_installed(path, &metadata, &artifact.target)?;
    Ok(())
}

#[cfg(test)]
#[path = "update_tests/mod.rs"]
mod tests;
