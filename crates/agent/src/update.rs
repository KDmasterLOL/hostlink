//! Installed-Agent update through the upstream GitHub bundle publisher.
//! Keep the source manifest verbatim and store the pinned ZIP digest alongside it.

use crate::{
    agent_files::{github_token, validate_user_owned_root},
    package::{
        ARCHIVE_DIGEST, EXECUTABLE_BASE, MAX_ARCHIVE_BYTES, PACKAGE_MANIFEST, PackageManifest,
        invalid, read_installed, read_regular, validate_contents, validate_installed,
    },
    private_fs::PrivateFileExt,
};
use hex::FromHex;
use private_fs::{FileAccess, FileCreation, OpenOptions, PrivateDir};
use secrecy::ExposeSecret;
use self_update::{
    Checksum, ReleaseAsset, ReleaseStatus,
    backends::github::{Update, UpdateBuilder},
    http_client::{HeaderMap, HttpClient, HttpResponse, UreqClient, header},
};
use semver::Version;
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

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

/// Install an exact version (including downgrades), or GitHub's latest stable
/// published release. Only the private target-user credential file is read.
///
/// # Errors
/// Rejects unsafe installed state, inaccessible/unpublished releases, ambiguous
/// target assets, absent SHA-256, integrity failures and publication errors.
pub fn update_from_github(root: &Path, version: Option<&Version>) -> io::Result<bool> {
    let token = github_token()?;
    let mut updater = Update::configure();
    updater.auth_token(token.expose_secret());
    apply_update(root, version, updater, Arc::new(GitHubTransport::new(true)))
}

// Production and synthetic HTTP fixtures use this same selection/publication path.
fn apply_update(
    root: &Path,
    requested: Option<&Version>,
    mut updater: UpdateBuilder,
    transport: Arc<GitHubTransport>,
) -> io::Result<bool> {
    validate_user_owned_root(root)?;
    // Both private locks stay held through discovery, verification and publication.
    // The runner owns its SQLite state; never inspect it to decide whether to update.
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
    let target = old.target;
    updater
        .repo_owner("KDmasterLOL")
        .repo_name("hostlink")
        .current_version(&old.version)
        .bin_name(EXECUTABLE_BASE)
        .target(&target)
        .retries(0)
        .http_client(transport.clone());
    let discovery = updater.build().map_err(io::Error::other)?;
    let release = match requested {
        None => discovery.get_latest_release().and_then(|releases| {
            releases
                .into_vec()
                .pop()
                .ok_or_else(self_update::Error::no_release_found)
        }),
        Some(version) => match discovery.get_release_version(&format!("v{version}")) {
            // Retry the other spelling only on 404, never auth/network errors.
            Err(self_update::Error::NotFound { .. }) => {
                discovery.get_release_version(&version.to_string())
            }
            result => result,
        },
    };
    let release = release.map_err(|error| {
        io::Error::other(format!(
            "no matching published release accessible for KDmasterLOL/hostlink; check target-user GitHub credential and Contents: Read access (repository may have no releases): {error}"
        ))
    })?;
    let version = Version::parse(release.version()).map_err(io::Error::other)?;
    if requested.is_some_and(|requested| *requested != version) {
        return Err(invalid("GitHub release differs from requested version"));
    }
    let (asset, sha256) = select_github_asset(release.assets(), &target)?;
    let old_version = Version::parse(&old.version).map_err(io::Error::other)?;
    if old_sha256 == sha256 {
        if old_version != version {
            return Err(invalid(
                "installed version conflicts with selected archive SHA-256",
            ));
        }
        return Ok(false);
    }
    if requested.is_none() && !version.cmp_precedence(&old_version).is_gt() {
        return Ok(false);
    }

    let version = version.to_string();
    let archive_target = target.clone();
    let archive_version = version.clone();
    let bundle_target = target.clone();
    let bundle_version = version.clone();
    let bundle_sha256 = hex::encode(sha256);
    let asset = asset.clone();
    let asset_target = target.clone();
    let status = updater
        // Upstream's unpinned update walks /releases, losing /latest semantics.
        // Pin the exact raw tag captured before its parser strips a leading 'v'.
        .release_tag(
            transport
                .publication
                .get()
                .ok_or_else(|| invalid("missing GitHub release tag"))?
                .tag_name
                .as_str(),
        )
        .asset_matcher(move |assets| {
            let (selected, _) = select_github_asset(assets, &asset_target).ok()?;
            (selected.download_url() == asset.download_url() && selected.digest() == asset.digest())
                .then(|| selected.clone())
        })
        .bundle_path_in_archive(format!("hostlink-agent-{target}"))
        .bundle_install_path(root.join("bin"))
        .unattended()
        // Mandatory even though upstream skips a missing API digest by default.
        .verify_checksum(Checksum::Sha256(hex::encode(sha256)))
        .verify_release_digest(false) // The same mandatory digest is already pinned above.
        .verify_archive(move |archive| {
            validate_contents(archive, &archive_target, &archive_version)?;
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

fn select_github_asset<'a>(
    assets: &'a [ReleaseAsset],
    target: &str,
) -> io::Result<(&'a ReleaseAsset, [u8; 32])> {
    let name = format!("hostlink-agent-{target}.zip");
    let mut assets = assets.iter().filter(|asset| asset.name() == name);
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
    // GitHub supplies canonical API URLs. A fixed prefix and numeric suffix
    // exclude foreign repositories, credentials, alternate schemes and queries.
    let asset_id = asset
        .download_url()
        .strip_prefix("https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/");
    if !asset_id.is_some_and(|id| {
        !id.is_empty()
            && id.bytes().all(|byte| byte.is_ascii_digit())
            && id.parse::<u64>().is_ok_and(|id| id > 0)
    }) {
        return Err(invalid(
            "exact credential-free GitHub API release asset URL required",
        ));
    }
    Ok((asset, sha256))
}

const MAX_METADATA_BYTES: u64 = 1024 * 1024;

// Upstream discards publication flags and raw tags. Keep only the missing policy,
// body bounds and redirect restrictions; parsing, auth and HTTP errors remain upstream.
struct GitHubTransport {
    metadata: Box<dyn HttpClient>,
    assets: Box<dyn HttpClient>,
    publication: OnceLock<Publication>,
}

impl GitHubTransport {
    fn new(https_only: bool) -> Self {
        let client = |redirects| {
            Box::new(UreqClient::from(
                ureq::Agent::config_builder()
                    .https_only(https_only)
                    .max_redirects(redirects)
                    .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
                    .proxy(None)
                    .timeout_global(Some(Duration::from_secs(30)))
                    .build()
                    .new_agent(),
            )) as Box<dyn HttpClient>
        };
        Self {
            metadata: client(0),
            assets: client(5),
            publication: OnceLock::new(),
        }
    }
}

struct BoundedResponse {
    headers: HeaderMap,
    body: Box<dyn Read>,
}

impl HttpResponse for BoundedResponse {
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    fn body(self: Box<Self>) -> Box<dyn Read> {
        self.body
    }
}

impl HttpClient for GitHubTransport {
    fn get(
        &self,
        url: &str,
        headers: &HeaderMap,
        timeout: Option<Duration>,
    ) -> self_update::Result<Box<dyn HttpResponse>> {
        let asset = headers
            .get(header::ACCEPT)
            .is_some_and(|value| value == "application/octet-stream");
        let client = if asset { &self.assets } else { &self.metadata };
        let response = client.get(url, headers, timeout)?;
        let headers = response.headers().clone();
        let body: Box<dyn Read> = if asset {
            Box::new(response.body().take(MAX_ARCHIVE_BYTES + 1))
        } else {
            let mut bytes = Vec::new();
            response
                .body()
                .take(MAX_METADATA_BYTES + 1)
                .read_to_end(&mut bytes)?;
            let publication = validate_github_metadata(&bytes, url.ends_with("/latest"))?;
            if self.publication.get_or_init(|| publication.clone()) != &publication {
                return Err(invalid("GitHub release publication changed after selection").into());
            }
            Box::new(io::Cursor::new(bytes))
        };
        Ok(Box::new(BoundedResponse { headers, body }))
    }
}

#[derive(Clone, PartialEq, serde::Deserialize)]
struct Publication {
    draft: bool,
    prerelease: bool,
    tag_name: String,
}

fn validate_github_metadata(bytes: &[u8], latest: bool) -> io::Result<Publication> {
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(invalid("GitHub release metadata exceeds size limit"));
    }
    let publication: Publication = serde_json::from_slice(bytes)
        .map_err(|_| invalid("invalid GitHub release publication metadata"))?;
    let version = Version::parse(
        publication
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&publication.tag_name),
    )
    .map_err(|_| invalid("GitHub release tag must be X.Y.Z or vX.Y.Z"))?;
    if publication.draft || (latest && (publication.prerelease || !version.pre.is_empty())) {
        return Err(invalid(
            "published GitHub release required (latest must be stable)",
        ));
    }
    Ok(publication)
}

#[cfg(test)]
#[path = "update_tests/mod.rs"]
mod tests;
