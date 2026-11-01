//! GitHub-only raw executable updates; self_update owns download, verification and replacement.

use crate::{
    agent_files::github_token,
    executable::{asset_name, read_identity, read_installed},
    installation::validate_installation_root,
    package::{EXECUTABLE_NAME, invalid, verify_executable},
    private_fs::PrivateFileExt,
};
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use secrecy::ExposeSecret;
use self_update::{Checksum, backends::github::Update, update::ReleaseAsset};
use semver::Version;
use std::{
    fs::{self, File},
    io,
    path::Path,
    time::Duration,
};

/// Update a stopped Agent from the fixed private repository. An exact version may downgrade;
/// omitting it selects GitHub's latest stable release. Installed identity comes from the
/// installed executable even when a separate offline Windows updater is running.
///
/// # Errors
/// Refuses unsafe or alternate roots, active Agents, missing credentials,
/// ambiguous/missing raw assets, checksum failures and unsuccessful replacement.
pub fn update(root: &Path, requested: Option<&Version>) -> io::Result<bool> {
    validate_installation_root(root)?;
    let _update_lock = lock(root, "update.lock")?;
    let _runner_lock = lock(&root.join("jobs"), "runner.lock").map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(error.kind(), "stop the running Agent before updating")
        } else {
            error
        }
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
        .bin_name(EXECUTABLE_NAME)
        .bin_path_in_archive(EXECUTABLE_NAME)
        .bin_install_path(root.join("bin").join(EXECUTABLE_NAME))
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
    let discovery = github.build().map_err(io::Error::other)?;
    // Pin /latest explicitly: the backend's unpinned update scans /releases instead.
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
    let (asset, sha) = selected_asset(release.assets(), &installed.target)?;
    if requested.is_none() {
        let current = Version::parse(&installed.version).map_err(io::Error::other)?;
        if !version.cmp_precedence(&current).is_gt() {
            if version == current && installed_sha != sha {
                return Err(invalid(
                    "installed Agent digest differs from the latest published executable",
                ));
            }
            return Ok(false);
        }
    }
    if installed_sha == sha {
        if installed.version != version.to_string() {
            return Err(invalid(
                "installed version conflicts with GitHub raw asset digest",
            ));
        }
        return Ok(false);
    }
    let expected = crate::installation::BinaryIdentity {
        target: installed.target.clone(),
        version: version.to_string(),
    };
    let verified_identity = expected.clone();
    let status = github
        .release_tag(format!("v{version}"))
        // Re-fetching a tag must not change the exact selected asset or its digest.
        .asset_matcher(move |assets| {
            assets
                .iter()
                .find(|candidate| {
                    candidate.name() == asset.name()
                        && candidate.digest() == asset.digest()
                        && candidate.download_url() == asset.download_url()
                })
                .cloned()
        })
        .verify_checksum(Checksum::Sha256(sha.clone()))
        .verify_binary(move |binary| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(binary, fs::Permissions::from_mode(0o700))?;
            }
            verify_executable(binary)?;
            if read_identity(binary)? != verified_identity {
                return Err(
                    invalid("downloaded Agent build differs from the selected release").into(),
                );
            }
            Ok(())
        })
        .build()
        .map_err(io::Error::other)?
        .update_extended()
        .map_err(io::Error::other)?;
    if !status.is_updated() || status.version() != Some(expected.version.as_str()) {
        return Err(invalid(
            "self_update did not install the exact selected GitHub release",
        ));
    }
    let (actual, actual_sha) = read_installed(root)?;
    if actual != expected || actual_sha != sha {
        return Err(invalid(
            "installed Agent differs from the selected GitHub release",
        ));
    }
    Ok(true)
}

fn lock(parent: &Path, name: &str) -> io::Result<File> {
    let file = PrivateDir::open(parent)
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
        .try_clone_std()?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => {
            io::Error::new(io::ErrorKind::WouldBlock, "Agent lock is held")
        }
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(file)
}

fn selected_asset(assets: &[ReleaseAsset], target: &str) -> io::Result<(ReleaseAsset, String)> {
    let name = asset_name(target)?;
    let mut matches = assets.iter().filter(|asset| asset.name() == name);
    let asset = matches
        .next()
        .ok_or_else(|| invalid("GitHub release lacks the exact Agent raw asset"))?;
    if matches.next().is_some() {
        return Err(invalid("GitHub release has ambiguous Agent raw assets"));
    }
    let digest = asset
        .digest()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| invalid("GitHub Agent raw asset lacks a SHA-256 digest"))?;
    let mut sha = [0_u8; 32];
    hex::decode_to_slice(digest, &mut sha).map_err(|_| invalid("invalid GitHub asset SHA-256"))?;
    Ok((asset.clone(), hex::encode(sha)))
}

#[cfg(test)]
#[path = "update_tests/credentials.rs"]
mod credential_tests;
#[cfg(test)]
#[path = "update_tests/raw.rs"]
mod raw_tests;
