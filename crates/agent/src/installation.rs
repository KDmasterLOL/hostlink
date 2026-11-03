//! Fresh binary-only installation at the single stable current-user root.

pub use crate::executable::{BinaryIdentity, current_binary_identity};
use crate::{
    agent_files::{hash_file, validate_path_has_no_reparse_components, validate_user_owned_root},
    enrollment::{EnrollmentOptions, EnrollmentResult, prepare_enrollment_with_ca},
    executable::RunningExecutable,
    package::{EXECUTABLE_NAME, MAX_EXECUTABLE_BYTES, invalid, verify_executable},
};
use private_fs::{Durability, PrivateDir};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Inputs to a fresh install. The installation directory is never caller-selected.
#[derive(Clone, Debug)]
pub struct InstallOptions {
    /// HTTPS Hub origin.
    pub hub_url: String,
    /// Private file containing a one-use enrollment token.
    pub token_file: PathBuf,
    /// Canonical Hub machine name.
    pub name: String,
    /// SSH account name served by this Agent.
    pub user: String,
    /// Zero-based index of the selected Hub-approved gateway.
    pub gateway_index: Option<usize>,
}

/// Resolve the stable per-user Agent location, independently of the running executable.
///
/// # Errors
/// Rejects unsupported platforms and missing absolute per-user data locations.
pub fn installation_root() -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        crate::agent_files::local_app_data_path().map(|base| base.join("HostLink/Agent"))
    }
    #[cfg(target_os = "linux")]
    {
        root_from_data(
            std::env::var_os("XDG_DATA_HOME").as_deref().map(Path::new),
            std::env::var_os("HOME").as_deref().map(Path::new),
        )
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(invalid("unsupported Agent installation platform"))
    }
}

#[cfg(target_os = "linux")]
fn root_from_data(xdg: Option<&Path>, home: Option<&Path>) -> io::Result<PathBuf> {
    let base = match xdg.filter(|path| path.is_absolute()) {
        Some(path) => path.to_owned(),
        None => home
            .filter(|path| path.is_absolute())
            .ok_or_else(|| invalid("absolute HOME or XDG_DATA_HOME required for installation"))?
            .join(".local/share"),
    };
    let root = base.join("hostlink/Agent");
    if root
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid(
            "Agent installation path must not contain traversal",
        ));
    }
    Ok(root)
}

/// Enforce the one installation root and private filesystem ownership before updating it.
///
/// # Errors
/// Refuses alternate, linked, missing or non-private installation directories.
pub fn validate_installation_root(root: &Path) -> io::Result<()> {
    let expected = installation_root()?;
    #[cfg(not(windows))]
    if root != expected {
        return Err(invalid(
            "Agent root must be the stable current-user data location",
        ));
    }
    validate_user_owned_root(root)?;
    #[cfg(windows)]
    if root.canonicalize()? != expected.canonicalize()? {
        return Err(invalid(
            "Agent root must be current-user LocalAppData/HostLink/Agent",
        ));
    }
    PrivateDir::open(
        root.parent()
            .ok_or_else(|| invalid("Agent root has no parent"))?,
    )
    .map_err(io::Error::other)?;
    Ok(())
}

/// Enroll once and publish the already bootstrap-verified running executable.
///
/// The disposable Controller bootstrap owns download and published-SHA verification before
/// this command starts. No GitHub credential is read here. An uncertain Hub response or a
/// failed publication leaves the enrollment pending marker for manual reconciliation.
///
/// # Errors
/// Refuses existing roots, unsafe staging/data paths, failed enrollment or failed publication.
pub async fn install(
    options: &InstallOptions,
    hub_ca_cert: Option<&Path>,
) -> io::Result<EnrollmentResult> {
    crate::executable::asset_name(self_update::get_target())?;
    let root = installation_root()?;
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(invalid(
                "Agent install root already exists; never adopt or retry it",
            ));
        }
    }
    let mut source = RunningExecutable::open()?;
    let parent = root
        .parent()
        .ok_or_else(|| invalid("Agent root has no parent"))?;
    ensure_parent(parent)?;
    PrivateDir::open(parent).map_err(io::Error::other)?;
    let result =
        prepare_enrollment_with_ca(&enrollment_options(options, root.clone()), hub_ca_cert).await?;
    publish_executable(&root, &mut source).map_err(|error| io::Error::other(format!(
        "Agent installation incomplete; preserve enrollment.pending and reconcile the Hub before retrying ({error})")))?;
    Ok(result)
}

fn enrollment_options(options: &InstallOptions, root: PathBuf) -> EnrollmentOptions {
    EnrollmentOptions {
        hub_url: options.hub_url.clone(),
        token_file: options.token_file.clone(),
        install_root: root,
        name: options.name.clone(),
        user: options.user.clone(),
        gateway_index: options.gateway_index,
        retain_pending: true,
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_path_has_no_reparse_components(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            ensure_parent(
                path.parent()
                    .ok_or_else(|| invalid("missing installation ancestor"))?,
            )?;
            PrivateDir::ensure(path)
                .map(|_| ())
                .map_err(io::Error::other)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn publish_executable(root: &Path, source: &mut RunningExecutable) -> io::Result<()> {
    let dir = PrivateDir::open(root).map_err(io::Error::other)?;
    dir.open_file("enrollment.pending")
        .map_err(io::Error::other)?;
    // Only a successful enrollment can call publication. State/manifest.json is private
    // enrollment metadata, deliberately independent of executable release metadata.
    PrivateDir::open(root.join("state"))
        .and_then(|state| state.open_file("manifest.json"))
        .map_err(io::Error::other)?;
    let bin = dir.create_dir("bin").map_err(io::Error::other)?;
    let name = EXECUTABLE_NAME;
    let mut output = bin.create(name).map_err(io::Error::other)?;
    let copied = io::copy(
        &mut (&mut source.file).take(MAX_EXECUTABLE_BYTES + 1),
        &mut output,
    )?;
    if copied == 0 || copied > MAX_EXECUTABLE_BYTES {
        return Err(invalid("running Agent copy is empty or oversized"));
    }
    output.sync_all().map_err(io::Error::other)?;
    drop(output);
    let executable = root.join("bin").join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    }
    verify_executable(&executable)?;
    if hash_file(&executable, MAX_EXECUTABLE_BYTES)? != source.sha256 {
        return Err(invalid(
            "published executable differs from the verified running image",
        ));
    }
    #[cfg(unix)]
    bin.sync_all().map_err(io::Error::other)?;
    dir.remove_file("enrollment.pending", Durability::Full)
        .map_err(io::Error::other)?;
    Ok(())
}

#[cfg(test)]
#[path = "installation_tests.rs"]
mod tests;
