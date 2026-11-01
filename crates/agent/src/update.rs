//! A single installed-Agent update using the upstream self_update bundle swap.
//! The source ZIP manifest remains unchanged; only its pinned archive digest is
//! added alongside it, so the installed bundle retains its exact source identity.

use crate::{
    agent_files::validate_user_owned_root,
    package::{
        ARCHIVE_DIGEST, EXECUTABLE_BASE, PACKAGE_MANIFEST, PackageManifest, invalid,
        read_installed, read_regular, target_matches_runtime, validate_contents,
        validate_installed, validate_sha256,
    },
    private_fs::PrivateFileExt,
};
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use self_update::{
    Checksum, Release, ReleaseAsset, ReleaseSource, ReleaseStatus, backends::custom::Update,
};
use std::{
    fs::{self, File},
    io,
    path::Path,
    time::Duration,
};

// self_update requires a ReleaseSource even for a caller-pinned single URL.
// Its GitHub backend would change both the source-selection and trust contract.
#[derive(Clone)]
struct SelectedRelease(Release);

impl ReleaseSource for SelectedRelease {
    fn get_releases(&self) -> self_update::Result<Vec<Release>> {
        Ok(vec![self.0.clone()])
    }
}

/// Update one stopped Agent from an independently pinned release.
/// Returns true when a bundle was installed, false when already current.
/// No task registration, Agent restart, or durable crash recovery is performed.
/// The caller must authorize the archive SHA-256 independently of the URL.
///
/// # Errors
/// Returns an error for invalid selections, unsafe or busy installation roots,
/// download failures, integrity mismatches, or publication failures.
pub fn update(
    root: &Path,
    url: &str,
    sha256: &str,
    target: &str,
    version: &str,
) -> io::Result<bool> {
    validate_sha256(sha256)?;
    semver::Version::parse(version).map_err(|_| invalid("exact semantic version required"))?;
    if !target_matches_runtime(target) {
        return Err(invalid("unsupported Agent target for this runtime"));
    }
    let address = reqwest::Url::parse(url).map_err(|_| invalid("invalid artifact URL"))?;
    let test_loopback = cfg!(test)
        && address.scheme() == "http"
        && address.host_str() == Some("127.0.0.1")
        && address.port().is_some_and(|port| port != 0);
    if (address.scheme() != "https" && !test_loopback)
        || address.host_str().is_none()
        || address.port() == Some(0)
        || !address.username().is_empty()
        || address.password().is_some()
        || address.fragment().is_some()
    {
        return Err(invalid("credential-free HTTPS artifact URL required"));
    }
    if !root.is_absolute() {
        return Err(invalid("Agent install root must be absolute"));
    }
    validate_user_owned_root(root)?;
    // These handles remain alive until publication completes. The runner holds
    // jobs/runner.lock for its lifetime; this must never query its SQLite state.
    let lock_file = |parent: &Path, name: &str| -> io::Result<File> {
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
    let _update_lock = lock_file(root, "update.lock")?;
    _update_lock.try_lock()?;
    let _runner_lock = lock_file(&root.join("jobs"), "runner.lock")?;
    _runner_lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "stop the running Agent before updating",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    #[cfg(windows)]
    crate::service::ensure_agent_offline(root)?;

    let (old, old_sha256) = read_installed(root)?;
    if old.target != target {
        return Err(invalid(
            "selected Agent target differs from installed target",
        ));
    }
    if old_sha256 == sha256 {
        if old.version != version {
            return Err(invalid(
                "installed version conflicts with selected archive SHA-256",
            ));
        }
        return Ok(false);
    }

    let release = Release::builder()
        .version(version)
        .asset(ReleaseAsset::new(
            format!("hostlink-agent-{target}.zip"),
            address.as_str(),
        ))
        .build()
        .map_err(io::Error::other)?;
    let verified_target = target.to_owned();
    let verified_version = version.to_owned();
    let bundle_target = target.to_owned();
    let bundle_version = version.to_owned();
    let bundle_sha256 = sha256.to_owned();
    let transport = ureq::Agent::config_builder()
        .https_only(address.scheme() == "https")
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent();

    let status = Update::configure()
        .source(SelectedRelease(release))
        .release_tag(version)
        .current_version(&old.version)
        .target(target)
        .bin_name(EXECUTABLE_BASE)
        .bundle_path_in_archive(format!("hostlink-agent-{target}"))
        .bundle_install_path(root.join("bin"))
        .no_confirm(true)
        .show_output(false)
        .ureq_agent(transport)
        .verify_checksum(Checksum::Sha256(sha256.to_owned()))
        .verify_archive(move |archive| {
            validate_contents(archive, &verified_target, &verified_version)?;
            Ok(())
        })
        .verify_binary(move |bundle| {
            let manifest: PackageManifest =
                serde_json::from_slice(&read_regular(&bundle.join(PACKAGE_MANIFEST))?)?;
            if manifest.version != bundle_version || manifest.target != bundle_target {
                return Err(invalid("extracted manifest differs from selected release").into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = bundle.join(EXECUTABLE_BASE);
                let mode = fs::metadata(&executable)?.permissions().mode();
                fs::set_permissions(executable, fs::Permissions::from_mode(mode | 0o100))?;
            }
            fs::write(bundle.join(ARCHIVE_DIGEST), &bundle_sha256)?;
            Ok(validate_installed(bundle, &manifest, &bundle_target)?)
        })
        .build()
        .map_err(io::Error::other)?
        .update_extended()
        .map_err(io::Error::other)?;

    if !matches!(status, ReleaseStatus::Updated(ref release) if release.version() == version) {
        return Err(invalid(
            "self_update did not install the exact pinned release",
        ));
    }
    let (installed, installed_sha256) = read_installed(root)?;
    if installed.version != version || installed_sha256 != sha256 {
        return Err(invalid(
            "published Agent identity differs from selected release",
        ));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "update_tests/mod.rs"]
mod tests;
