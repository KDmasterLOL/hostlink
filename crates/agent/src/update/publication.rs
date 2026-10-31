//! Upstream download/checksum/extract/bundle-swap, with HostLink identity hooks.

use super::{
    AgentUpdateRequest, INSTALL_METADATA, PACKAGE_MANIFEST,
    archive::validate_contents,
    installed::{read, read_regular, validate_installed},
    invalid,
    manifest::{InstallMetadata, PackageManifest},
};
use self_update::{Checksum, ReleaseStatus, backends::custom::Update};
use std::{
    fs, io,
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

pub(super) fn update(request: &AgentUpdateRequest, old: &InstallMetadata) -> io::Result<()> {
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
    let installed = read(&request.install_root)?;
    if installed.installed_package_sha256 != artifact.sha256
        || installed.installed_version != artifact.version
    {
        return Err(invalid(
            "published Agent identity differs from the selected artifact",
        ));
    }
    Ok(())
}

pub(super) fn prepare_bundle(
    path: &Path,
    artifact: &super::Artifact,
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
        let executable = path.join(super::EXECUTABLE_BASE);
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
    if bytes.len() as u64 > super::MAX_MANIFEST_BYTES {
        return Err(invalid("generated install metadata exceeds its size limit"));
    }
    fs::write(path.join(INSTALL_METADATA), bytes)?;
    validate_installed(path, &metadata, &artifact.target)?;
    Ok(())
}
