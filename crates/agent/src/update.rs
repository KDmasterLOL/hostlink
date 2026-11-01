//! A single installed-Agent update using the upstream self_update bundle swap.
//! The source ZIP manifest remains unchanged; only its pinned archive digest is
//! added alongside it, so the installed bundle retains its exact source identity.

use crate::{
    agent_files::validate_user_owned_root,
    package::{
        ARCHIVE_DIGEST, EXECUTABLE_BASE, PACKAGE_MANIFEST, PackageManifest, invalid,
        read_installed, read_regular, target_matches_runtime, validate_contents,
        validate_installed,
    },
    private_fs::PrivateFileExt,
};
use hex::FromHex;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use reqwest::Url;
use self_update::{
    Checksum, Release, ReleaseAsset, ReleaseSource, ReleaseStatus,
    backends::{
        custom::Update, custom::UpdateBuilder, github::ReleaseList, github::Update as GitHubUpdate,
    },
};
use semver::Version;
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

// Both discovery paths pin one release before entering the same bundle publisher.
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
    url: &Url,
    sha256: [u8; 32],
    target: &str,
    version: &Version,
) -> io::Result<bool> {
    let mut publisher = Update::configure();
    publisher.ureq_agent(download_transport(url.scheme() == "https", 0));
    apply_selected(root, url, sha256, target, version, publisher, false)
}

/// Resolve the installed Agent root without guessing a Linux installer suffix.
///
/// # Errors
/// Returns an error unless the running Linux executable is the verified installed
/// ROOT/bin/hostlink-agent, or the Windows OS profile path can be resolved.
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
        validate_user_owned_root(root)?;
        read_installed(root)?;
        Ok(root.to_owned())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    Err(invalid("unsupported Agent platform; specify --root"))
}

/// Select an exact release, or GitHub's designated latest published release,
/// from the authenticated GitHub API. A missing/inaccessible release is an
/// error, never an already-current result. The token is used only in memory.
/// GitHub's digest authenticates API-selected bytes; it is not a publisher signature.
///
/// # Errors
/// Returns an error for invalid installed state, unavailable releases, unsafe asset
/// metadata, failed integrity verification, or publication failure.
pub fn update_from_github(
    root: &Path,
    version: Option<&Version>,
    token: Option<&str>,
) -> io::Result<bool> {
    validate_user_owned_root(root)?;
    let (installed, _) = read_installed(root)?;
    let mut listing = ReleaseList::configure();
    listing
        .repo_owner("KDmasterLOL")
        .repo_name("hostlink")
        .ureq_agent(download_transport(true, 0));
    let mut publisher = Update::configure();
    publisher
        .ureq_agent(download_transport(true, 5))
        .request_header(
            self_update::http::header::ACCEPT,
            "application/octet-stream",
        );
    if let Some(token) = token {
        if token.is_empty()
            || token.len() > 8192
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid("invalid GitHub API token"));
        }
        listing.auth_token(token);
        // self_update marks Authorization sensitive. ureq removes it on EVERY
        // redirect (even same-host), so a different origin/port never gets it.
        publisher.request_header(
            self_update::http::header::AUTHORIZATION,
            format!("Bearer {token}"),
        );
    }
    // A private repository's authenticated /releases list may expose DRAFTS
    // to users with write access. The official /releases/latest endpoint
    // excludes unpublished drafts and pre-releases. Use it for the default.
    let releases = if version.is_none() {
        let mut latest = GitHubUpdate::configure();
        latest
            .repo_owner("KDmasterLOL")
            .repo_name("hostlink")
            .current_version(&installed.version)
            .bin_name(EXECUTABLE_BASE)
            .target(&installed.target)
            .ureq_agent(download_transport(true, 0));
        if let Some(token) = token {
            latest.auth_token(token);
        }
        latest
            .build()
            .map_err(io::Error::other)?
            .get_latest_release()
            .map_err(|error| {
                io::Error::other(format!(
                    "no published latest release accessible for KDmasterLOL/hostlink: {error}"
                ))
            })?
            .into_vec()
    } else {
        listing
            .build()
            .map_err(io::Error::other)?
            .fetch()
            .map_err(|error| {
                io::Error::other(format!(
                    "cannot list private KDmasterLOL/hostlink releases; check GitHub API access: {error}"
                ))
            })?
            .into_vec()
    };
    let (url, sha256, selected_version) =
        select_github_asset(&releases, &installed.target, version)?;
    apply_selected(
        root,
        &url,
        sha256,
        &installed.target,
        &selected_version,
        publisher,
        version.is_none(),
    )
}

fn select_github_asset(
    releases: &[Release],
    target: &str,
    requested: Option<&Version>,
) -> io::Result<(Url, [u8; 32], Version)> {
    let name = format!("hostlink-agent-{target}.zip");
    let mut selected: Option<(&Release, Version)> = None;
    for release in releases {
        let version = Version::parse(release.version())
            .map_err(|_| invalid("GitHub release version is not semantic"))?;
        if let Some(requested) = requested {
            if &version != requested {
                continue;
            }
        } else if !version.pre.is_empty()
            || !release.assets().iter().any(|asset| asset.name() == name)
        {
            continue;
        }
        if let Some((_, current)) = &selected {
            match version.cmp_precedence(current) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Equal => {
                    return Err(invalid("ambiguous GitHub release version"));
                }
                std::cmp::Ordering::Greater => {}
            }
        }
        selected = Some((release, version));
    }
    let (release, version) = selected.ok_or_else(|| {
        invalid("no matching published HostLink Agent release; repository may have no releases")
    })?;
    let mut assets = release.assets().iter().filter(|asset| asset.name() == name);
    let asset = assets
        .next()
        .ok_or_else(|| invalid("GitHub release lacks the exact Agent target asset"))?;
    if assets.next().is_some() {
        return Err(invalid("ambiguous GitHub Agent target asset"));
    }
    let sha256 = asset
        .digest()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .ok_or_else(|| invalid("GitHub Agent asset requires an API sha256 digest"))?;
    let sha256 = <[u8; 32]>::from_hex(sha256)
        .map_err(|_| invalid("GitHub Agent asset SHA-256 must contain 32 hexadecimal bytes"))?;
    let url =
        Url::parse(asset.download_url()).map_err(|_| invalid("invalid GitHub API asset URL"))?;
    let asset_id = url
        .path()
        .strip_prefix("/repos/KDmasterLOL/hostlink/releases/assets/");
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || !asset_id.is_some_and(|id| {
            !id.is_empty()
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && id.parse::<u64>().is_ok_and(|id| id > 0)
        })
    {
        return Err(invalid(
            "exact credential-free GitHub API release asset URL required",
        ));
    }
    Ok((url, sha256, version))
}

fn download_transport(https_only: bool, max_redirects: u32) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(https_only)
        .max_redirects(max_redirects)
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent()
}

// Single publication body: selection and transport differ, all install gates do not.
fn apply_selected(
    root: &Path,
    address: &Url,
    sha256: [u8; 32],
    target: &str,
    version: &Version,
    mut publisher: UpdateBuilder,
    only_newer: bool,
) -> io::Result<bool> {
    if !target_matches_runtime(target) {
        return Err(invalid("unsupported Agent target for this runtime"));
    }
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
    let old_version = Version::parse(&old.version)
        .map_err(|_| invalid("installed Agent version is not semantic"))?;
    if old_sha256 == sha256 {
        if old_version != *version {
            return Err(invalid(
                "installed version conflicts with selected archive SHA-256",
            ));
        }
        return Ok(false);
    }

    if only_newer && !version.cmp_precedence(&old_version).is_gt() {
        return Ok(false);
    }
    let version = version.to_string();
    let release = Release::builder()
        .version(&version)
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
    let bundle_sha256 = hex::encode(sha256);
    let status = publisher
        .source(SelectedRelease(release))
        .release_tag(&version)
        .current_version(&old.version)
        .target(target)
        .bin_name(EXECUTABLE_BASE)
        .bundle_path_in_archive(format!("hostlink-agent-{target}"))
        .bundle_install_path(root.join("bin"))
        .no_confirm(true)
        .show_output(false)
        .verify_checksum(Checksum::Sha256(hex::encode(sha256)))
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
    if installed.version != version || installed.target != target || installed_sha256 != sha256 {
        return Err(invalid(
            "published Agent identity differs from selected release",
        ));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "update_tests/mod.rs"]
mod tests;
