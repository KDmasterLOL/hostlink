//! GitHub-only Agent bundle update. self_update owns network, ZIP extraction and swap.

use crate::{
    agent_files::{github_token, validate_user_owned_root},
    package::{
        ARCHIVE_DIGEST, EXECUTABLE_BASE, PACKAGE_MANIFEST, PackageManifest, invalid,
        read_installed, read_regular, validate_contents, validate_installed,
    },
    private_fs::PrivateFileExt,
};
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use secrecy::ExposeSecret;
use self_update::{Checksum, backends::github::Update};
use semver::Version;
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

/// Resolve an installed Agent, not an arbitrary development executable.
///
/// # Errors
/// Returns an error when the running binary is not the installed Agent.
pub fn default_update_root() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        crate::agent_files::local_app_data_path().map(|path| path.join("HostLink").join("Agent"))
    }
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::current_exe()?;
        let root = executable
            .parent()
            .filter(|bin| bin.file_name().is_some_and(|name| name == "bin"))
            .and_then(Path::parent)
            .filter(|_| {
                executable
                    .file_name()
                    .is_some_and(|name| name == EXECUTABLE_BASE)
            })
            .ok_or_else(|| {
                invalid("running outside installed ROOT/bin/hostlink-agent; specify --root")
            })?;
        Ok(root.to_owned())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    Err(invalid("unsupported Agent platform"))
}

/// Update from a private GitHub Release. A selected version can downgrade;
/// without a version, use GitHub's latest published stable Release.
///
/// # Errors
/// Returns an error if authentication, package identity, checksum or offline
/// installation admission fails.
pub fn update(root: &Path, requested: Option<&Version>) -> io::Result<bool> {
    validate_user_owned_root(root)?;

    // Hold both locks through the download and bundle swap. The running Agent
    // already holds runner.lock; its SQLite queue must not be inspected here.
    let lock = |parent: &Path, name: &str| -> io::Result<File> {
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
    let update_lock = lock(root, "update.lock")?;
    update_lock.try_lock()?;
    let runner_lock = lock(&root.join("jobs"), "runner.lock")?;
    runner_lock.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "stop the running Agent before updating",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    #[cfg(windows)]
    crate::service::ensure_agent_offline(root)?;

    let (installed, installed_sha) = read_installed(root)?;
    let token = github_token()?;
    let mut github = Update::configure();
    github
        .repo_owner("KDmasterLOL")
        .repo_name("hostlink")
        .current_version(&installed.version)
        .bin_name(EXECUTABLE_BASE)
        .target(&installed.target)
        .auth_token(token.expose_secret())
        .unattended()
        .retries(0)
        .ureq_agent(
            ureq::Agent::config_builder()
                .https_only(true)
                .proxy(None)
                .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
                .timeout_global(Some(Duration::from_secs(30)))
                .build()
                .new_agent(),
        );

    // The library's unpinned update() scans /releases and may pick a different
    // version. Pin the exact GitHub /latest release before installing it.
    let discovery = github.build().map_err(io::Error::other)?;
    let release = if let Some(version) = requested {
        discovery
            .get_release_version(&format!("v{version}"))
            .map_err(io::Error::other)?
    } else {
        discovery
            .get_latest_release()
            .map_err(io::Error::other)?
            .into_vec()
            .pop()
            .ok_or_else(|| invalid("no published HostLink release on GitHub"))?
    };
    let version = Version::parse(release.version()).map_err(io::Error::other)?;
    if requested.is_some_and(|requested| *requested != version) {
        return Err(invalid("GitHub release differs from the requested version"));
    }
    if requested.is_none()
        && !version
            .cmp_precedence(&Version::parse(&installed.version).map_err(io::Error::other)?)
            .is_gt()
    {
        return Ok(false);
    }

    // The backend matches asset names by substring by default. Select the
    // platform-specific ZIP explicitly; GitHub requires unique asset names.
    let name = format!("hostlink-agent-{}.zip", installed.target);
    let asset = release
        .assets()
        .iter()
        .find(|asset| asset.name() == name)
        .ok_or_else(|| invalid("GitHub release lacks the Agent ZIP"))?;
    let digest = asset
        .digest()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| invalid("GitHub Agent ZIP lacks a SHA-256 digest"))?;
    let mut sha = [0_u8; 32];
    hex::decode_to_slice(digest, &mut sha)
        .map_err(|_| invalid("invalid GitHub release asset SHA-256"))?;
    if installed_sha == sha {
        if installed.version != version.to_string() {
            return Err(invalid(
                "installed version conflicts with GitHub ZIP digest",
            ));
        }
        return Ok(false);
    }

    let tag = format!("v{version}");
    let target = installed.target;
    let version = version.to_string();
    let digest = hex::encode(sha);
    let archive_target = target.clone();
    let archive_version = version.clone();
    let bundle_target = target.clone();
    let bundle_version = version.clone();
    let bundle_digest = digest.clone();

    let status = github
        .release_tag(tag)
        // The selected SHA-256 is pinned below; no second metadata comparison.
        .asset_matcher(move |assets| assets.iter().find(|asset| asset.name() == name).cloned())
        .bundle_path_in_archive(format!("hostlink-agent-{target}"))
        .bundle_install_path(root.join("bin"))
        .verify_checksum(Checksum::Sha256(digest))
        .verify_archive(move |archive| {
            validate_contents(archive, &archive_target, &archive_version)?;
            Ok(())
        })
        .verify_binary(move |bundle| {
            let manifest: PackageManifest =
                serde_json::from_slice(&read_regular(&bundle.join(PACKAGE_MANIFEST))?)?;
            if manifest.version != bundle_version || manifest.target != bundle_target {
                return Err(
                    invalid("extracted manifest differs from selected GitHub release").into(),
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = bundle.join(EXECUTABLE_BASE);
                let mode = fs::metadata(&executable)?.permissions().mode();
                fs::set_permissions(executable, fs::Permissions::from_mode(mode | 0o100))?;
            }
            fs::write(bundle.join(ARCHIVE_DIGEST), &bundle_digest)?;
            Ok(validate_installed(bundle, &manifest, &bundle_target)?)
        })
        .build()
        .map_err(io::Error::other)?
        .update_extended()
        .map_err(io::Error::other)?;
    if !status.is_updated() || status.version() != Some(version.as_str()) {
        return Err(invalid(
            "self_update did not install the exact selected GitHub release",
        ));
    }
    let (actual, actual_sha) = read_installed(root)?;
    if actual.target != target || actual.version != version || actual_sha != sha {
        return Err(invalid(
            "installed Agent differs from the selected GitHub release",
        ));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "update_tests/credentials.rs"]
mod credential_tests;
