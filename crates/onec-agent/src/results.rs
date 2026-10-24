//! Target-owned managed process result artifacts.
//!
//! Physical result paths never cross the control protocol. A child receives only one private
//! incoming directory through ONEC_RESULT_DIR; after the child stops, the agent copies declared
//! regular files through no-follow capability handles into an immutable published directory and
//! publishes a bounded manifest last.

#[cfg(windows)]
use cap_fs_ext::OsMetadataExt as _;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use hostlink_core::{
    create_private_directory, ensure_private_directory, move_file_atomically, remove_path_scoped,
    restrict_private_directory, write_new_json_file,
};
use hostlink_protocol::{
    ResultArtifactInfo, ResultArtifactSpec, ResultOwner, ResultSetInfo, validate_result_name,
    validate_result_set_id, validate_result_specs,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const EXEC_RESULTS_DIR: &str = ".exec-results";
const JOB_RESULTS_DIR: &str = "results";

pub(crate) fn job_result_set_cleaned(jobs_root: &Path, job_id: &str) -> io::Result<bool> {
    let path = jobs_root.join(job_id).join(JOB_RESULTS_DIR);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !std_metadata_is_symlink_or_reparse(&metadata) => {
            Ok(false)
        }
        Ok(_) => Err(invalid_data("job result path is not a regular directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}
const INCOMING_DIR: &str = "incoming";
const PUBLISHED_DIR: &str = "published";
const MANIFEST_FILE: &str = "manifest.json";
const RESULT_MANIFEST_VERSION: u32 = 1;
const RESULT_MANIFEST_MAX_BYTES: usize = 64 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
/// Immediate Exec is capped at ten minutes, so this retention safely exceeds any live request.
const EXEC_RESULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResultManifest {
    version: u32,
    result_set: ResultSetInfo,
}

/// One prepared result directory owned by a single managed child process.
pub(crate) struct ResultWorkspace {
    owner: ResultOwner,
    root_path: PathBuf,
    cleanup_root: PathBuf,
    root: Dir,
    incoming: Dir,
    incoming_path: PathBuf,
    specs: Vec<ResultArtifactSpec>,
}

impl ResultWorkspace {
    /// Creates one immediate-exec result workspace when declarations are present.
    pub(crate) fn prepare_exec(
        jobs_root: &Path,
        result_set_id: Option<&str>,
        specs: &[ResultArtifactSpec],
    ) -> io::Result<Option<Self>> {
        if specs.is_empty() {
            if result_set_id.is_some() {
                return Err(invalid_input(
                    "exec result_set_id requires at least one declared result artifact",
                ));
            }
            return Ok(None);
        }
        let result_set_id = result_set_id.ok_or_else(|| {
            invalid_input("exec result artifacts require a caller-known result_set_id")
        })?;
        validate_result_set_id(result_set_id).map_err(invalid_input)?;
        ensure_private_directory(jobs_root)?;
        let exec_root = jobs_root.join(EXEC_RESULTS_DIR);
        gc_expired_exec_result_sets(jobs_root, SystemTime::now())?;
        let root_path = exec_root.join(result_set_id);
        create_private_directory(&root_path)?;
        Self::prepare(
            ResultOwner::exec(result_set_id.to_owned()).map_err(invalid_input)?,
            exec_root,
            root_path,
            specs,
        )
        .map(Some)
    }

    /// Creates one durable-job result workspace under the already-owned job directory.
    pub(crate) fn prepare_job(
        job_dir: &Path,
        job_id: &str,
        specs: &[ResultArtifactSpec],
    ) -> io::Result<Option<Self>> {
        // Durable launch state is read back from disk after the request boundary.
        validate_result_specs_io(specs)?;
        if specs.is_empty() {
            return Ok(None);
        }
        validate_result_set_id(job_id).map_err(invalid_input)?;
        let root_path = job_dir.join(JOB_RESULTS_DIR);
        create_private_directory(&root_path)?;
        Self::prepare(
            ResultOwner::job(job_id.to_owned()).map_err(invalid_input)?,
            job_dir.to_path_buf(),
            root_path,
            specs,
        )
        .map(Some)
    }

    fn prepare(
        owner: ResultOwner,
        cleanup_root: PathBuf,
        root_path: PathBuf,
        specs: &[ResultArtifactSpec],
    ) -> io::Result<Self> {
        let root = Dir::open_ambient_dir(&root_path, ambient_authority())?;
        root.create_dir(INCOMING_DIR)?;
        let incoming_path = root_path.join(INCOMING_DIR);
        restrict_private_directory(&incoming_path).map_err(io::Error::other)?;
        let incoming = root.open_dir(INCOMING_DIR)?;
        Ok(Self {
            owner,
            root_path,
            cleanup_root,
            root,
            incoming,
            incoming_path,
            specs: specs.to_vec(),
        })
    }

    /// Returns the only physical directory exposed to the managed child.
    pub(crate) fn incoming_path(&self) -> &Path {
        &self.incoming_path
    }

    /// Checks every currently visible incoming entry against declaration/type/size policy.
    ///
    /// Missing declared files are allowed while the child is still running.
    pub(crate) fn supervise(&self) -> io::Result<()> {
        let declared = self.declared_by_name();
        let mut entries_seen = 0_usize;
        for entry in self.incoming.entries()? {
            let entry = entry?;
            entries_seen += 1;
            if entries_seen > self.specs.len() {
                return Err(invalid_data(format!(
                    "result directory contains more than {} declared entries",
                    self.specs.len()
                )));
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                invalid_data("result artifact filename is not valid portable UTF-8")
            })?;
            let Some(spec) = declared.get(name) else {
                return Err(invalid_data(format!("undeclared result artifact {name:?}")));
            };
            let metadata = self.incoming.symlink_metadata(name)?;
            validate_result_metadata(name, &metadata, spec.max_bytes())?;
        }
        Ok(())
    }

    /// Finalizes all declared artifacts and atomically publishes the manifest last.
    pub(crate) fn finalize(&self) -> io::Result<ResultSetInfo> {
        self.supervise()?;
        self.root.create_dir(PUBLISHED_DIR)?;
        let published_path = self.root_path.join(PUBLISHED_DIR);
        restrict_private_directory(&published_path).map_err(io::Error::other)?;
        let published = self.root.open_dir(PUBLISHED_DIR)?;

        let result = self.finalize_into(&published);
        if result.is_err() {
            drop(published);
            let _ = self.root.remove_dir_all(PUBLISHED_DIR);
        }
        let result_set = result?;
        let temp_name = format!(".manifest-{}.tmp", std::process::id());
        let temp_path = self.root_path.join(&temp_name);
        write_new_json_file(
            &temp_path,
            &ResultManifest {
                version: RESULT_MANIFEST_VERSION,
                result_set: result_set.clone(),
            },
        )?;
        if let Err(error) = move_file_atomically(&temp_path, &self.root_path.join(MANIFEST_FILE)) {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        // The immutable published copies plus manifest are authoritative after publication.
        // Remove the child-writable copies so retained result evidence does not consume payload
        // storage twice. Cleanup remains best-effort because publication is already committed.
        for spec in &self.specs {
            let _ = self.incoming.remove_file(spec.name());
        }
        Ok(result_set)
    }

    fn finalize_into(&self, published: &Dir) -> io::Result<ResultSetInfo> {
        let mut artifacts = Vec::with_capacity(self.specs.len());
        for spec in &self.specs {
            let metadata = self
                .incoming
                .symlink_metadata(spec.name())
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        invalid_data(format!(
                            "declared result artifact {:?} was not produced",
                            spec.name()
                        ))
                    } else {
                        error
                    }
                })?;
            validate_result_metadata(spec.name(), &metadata, spec.max_bytes())?;

            let mut source_options = OpenOptions::new();
            source_options.read(true);
            source_options.follow(FollowSymlinks::No);
            let mut source = self.incoming.open_with(spec.name(), &source_options)?;
            let opened_metadata = source.metadata()?;
            validate_result_metadata(spec.name(), &opened_metadata, spec.max_bytes())?;

            let mut destination_options = OpenOptions::new();
            destination_options.write(true).create_new(true);
            destination_options.follow(FollowSymlinks::No);
            let mut destination = published.open_with(spec.name(), &destination_options)?;

            let copied =
                copy_bounded_and_hash(&mut source, &mut destination, spec.max_bytes(), spec.name());
            let (bytes, sha256) = match copied {
                Ok(value) => value,
                Err(error) => {
                    drop(destination);
                    let _ = published.remove_file(spec.name());
                    return Err(error);
                }
            };
            destination.sync_all()?;
            artifacts.push(
                ResultArtifactInfo::try_new(
                    spec.name().to_owned(),
                    bytes,
                    sha256,
                    spec.media_type().map(str::to_owned),
                )
                .map_err(invalid_data)?,
            );
        }
        ResultSetInfo::try_new(self.owner.clone(), artifacts).map_err(invalid_data)
    }

    fn declared_by_name(&self) -> BTreeMap<&str, &ResultArtifactSpec> {
        self.specs.iter().map(|spec| (spec.name(), spec)).collect()
    }

    /// Removes this exact result workspace, including unpublished child output.
    pub(crate) fn discard(self) -> io::Result<bool> {
        let Self {
            root_path,
            cleanup_root,
            root,
            incoming,
            ..
        } = self;
        drop(incoming);
        drop(root);
        remove_path_scoped(&cleanup_root, &root_path, true, true)
    }
}

pub(crate) fn gc_expired_exec_result_sets(jobs_root: &Path, now: SystemTime) -> io::Result<usize> {
    ensure_private_directory(jobs_root)?;
    let exec_root = jobs_root.join(EXEC_RESULTS_DIR);
    ensure_owned_private_directory(&exec_root)?;
    let cutoff = now
        .checked_sub(EXEC_RESULT_RETENTION)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    gc_exec_result_sets_before(&exec_root, cutoff)
}

fn gc_exec_result_sets_before(exec_root: &Path, cutoff: SystemTime) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(exec_root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_result_set_id(&id).is_err()
            || !metadata.is_dir()
            || std_metadata_is_symlink_or_reparse(&metadata)
            || !metadata.modified().is_ok_and(|modified| modified <= cutoff)
        {
            continue;
        }
        if remove_path_scoped(exec_root, &entry.path(), true, true)? {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Opens one fully published artifact by typed owner and logical name.
pub(crate) fn open_published(
    jobs_root: &Path,
    owner: &ResultOwner,
    name: &str,
) -> io::Result<(ResultArtifactInfo, cap_std::fs::File)> {
    validate_result_name(name).map_err(invalid_input)?;
    let root = open_result_root(jobs_root, owner)?;
    let manifest = read_manifest(&root)?;
    if manifest.version != RESULT_MANIFEST_VERSION {
        return Err(invalid_data(format!(
            "unsupported result manifest version {}",
            manifest.version
        )));
    }
    if manifest.result_set.owner() != owner {
        return Err(invalid_data("result manifest owner mismatch"));
    }
    let artifact = manifest
        .result_set
        .artifacts()
        .iter()
        .find(|artifact| artifact.name() == name)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "result artifact not found"))?;
    let published = open_regular_child_dir(&root, PUBLISHED_DIR)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let file = published.open_with(name, &options)?;
    let metadata = file.metadata()?;
    validate_result_metadata(name, &metadata, artifact.bytes())?;
    if metadata.len() != artifact.bytes() {
        return Err(invalid_data(format!(
            "published result artifact {name:?} length changed from {} to {} bytes",
            artifact.bytes(),
            metadata.len()
        )));
    }
    Ok((artifact, file))
}

/// Removes one exact result set by typed owner without accepting an arbitrary path.
pub(crate) fn cleanup(jobs_root: &Path, owner: &ResultOwner) -> io::Result<bool> {
    let root_path = result_root_unchecked(jobs_root, owner)?;
    let cleanup_root = if owner.exec_id().is_some() {
        jobs_root.join(EXEC_RESULTS_DIR)
    } else {
        jobs_root.join(owner.job_id().expect("validated owner variant"))
    };
    if !cleanup_root.exists() || !root_path.exists() {
        return Ok(false);
    }

    // Cleanup is allowed only after publication completed. Requiring the immutable manifest keeps
    // a caller that already knows the logical owner from racing an active child and deleting its
    // incoming workspace.
    let root = open_result_root(jobs_root, owner)?;
    let manifest = read_manifest(&root)?;
    if manifest.version != RESULT_MANIFEST_VERSION || manifest.result_set.owner() != owner {
        return Err(invalid_data("result manifest does not match cleanup owner"));
    }
    drop(root);
    remove_path_scoped(&cleanup_root, &root_path, true, false)
}

fn result_root_unchecked(jobs_root: &Path, owner: &ResultOwner) -> io::Result<PathBuf> {
    if let Some(result_set_id) = owner.exec_id() {
        validate_result_set_id(result_set_id).map_err(invalid_input)?;
        return Ok(jobs_root.join(EXEC_RESULTS_DIR).join(result_set_id));
    }
    let job_id = owner.job_id().expect("validated owner variant");
    validate_result_set_id(job_id).map_err(invalid_input)?;
    Ok(jobs_root.join(job_id).join(JOB_RESULTS_DIR))
}

fn open_result_root(jobs_root: &Path, owner: &ResultOwner) -> io::Result<Dir> {
    let jobs = open_ambient_regular_dir(jobs_root)?;
    if let Some(result_set_id) = owner.exec_id() {
        validate_result_set_id(result_set_id).map_err(invalid_input)?;
        let exec = open_regular_child_dir(&jobs, EXEC_RESULTS_DIR)?;
        return open_regular_child_dir(&exec, result_set_id);
    }
    let job_id = owner.job_id().expect("validated owner variant");
    validate_result_set_id(job_id).map_err(invalid_input)?;
    let job = open_regular_child_dir(&jobs, job_id)?;
    open_regular_child_dir(&job, JOB_RESULTS_DIR)
}

fn open_ambient_regular_dir(path: &Path) -> io::Result<Dir> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || std_metadata_is_symlink_or_reparse(&metadata) {
        return Err(invalid_data(format!(
            "managed result root is not a regular directory: {}",
            path.display()
        )));
    }
    let dir = Dir::open_ambient_dir(path, ambient_authority())?;
    let opened = dir.dir_metadata()?;
    if !opened.is_dir() || is_symlink_or_reparse(&opened) {
        return Err(invalid_data(format!(
            "opened managed result root is not a regular directory: {}",
            path.display()
        )));
    }
    Ok(dir)
}

fn open_regular_child_dir(parent: &Dir, name: &str) -> io::Result<Dir> {
    let metadata = parent.symlink_metadata(name)?;
    if !metadata.is_dir() || is_symlink_or_reparse(&metadata) {
        return Err(invalid_data(format!(
            "managed result directory component {name:?} is not a regular directory"
        )));
    }
    let dir = parent.open_dir(name)?;
    let opened = dir.dir_metadata()?;
    if !opened.is_dir() || is_symlink_or_reparse(&opened) {
        return Err(invalid_data(format!(
            "opened managed result directory component {name:?} is not regular"
        )));
    }
    Ok(dir)
}

fn read_manifest(root: &Dir) -> io::Result<ResultManifest> {
    let metadata = root.symlink_metadata(MANIFEST_FILE)?;
    validate_result_metadata(MANIFEST_FILE, &metadata, RESULT_MANIFEST_MAX_BYTES as u64)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let mut file = root.open_with(MANIFEST_FILE, &options)?;
    let opened = file.metadata()?;
    validate_result_metadata(MANIFEST_FILE, &opened, RESULT_MANIFEST_MAX_BYTES as u64)?;
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(RESULT_MANIFEST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > RESULT_MANIFEST_MAX_BYTES {
        return Err(invalid_data(format!(
            "result manifest exceeds {RESULT_MANIFEST_MAX_BYTES} bytes"
        )));
    }
    let manifest: ResultManifest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid result manifest JSON: {error}")))?;
    Ok(manifest)
}

fn validate_result_specs_io(specs: &[ResultArtifactSpec]) -> io::Result<()> {
    validate_result_specs(specs).map_err(invalid_input)
}

fn validate_result_metadata(name: &str, metadata: &Metadata, max_bytes: u64) -> io::Result<()> {
    if is_symlink_or_reparse(metadata) || !metadata.is_file() {
        return Err(invalid_data(format!(
            "result artifact {name:?} must be a regular file, not a symlink/reparse/directory"
        )));
    }
    if metadata.len() > max_bytes {
        return Err(invalid_data(format!(
            "result artifact {name:?} exceeds its {max_bytes} byte limit ({} bytes observed)",
            metadata.len()
        )));
    }
    Ok(())
}

fn copy_bounded_and_hash(
    source: &mut cap_std::fs::File,
    destination: &mut cap_std::fs::File,
    max_bytes: u64,
    name: &str,
) -> io::Result<(u64, String)> {
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(invalid_data(format!(
                "result artifact {name:?} grew beyond its {max_bytes} byte limit while publishing"
            )));
        }
        destination.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

fn ensure_owned_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || std_metadata_is_symlink_or_reparse(&metadata) {
                return Err(invalid_data(format!(
                    "managed result directory must be a regular directory: {}",
                    path.display()
                )));
            }
            restrict_private_directory(path).map_err(io::Error::other)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_private_directory(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    ensure_owned_private_directory(path)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn is_symlink_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

pub(crate) fn std_metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn spec(name: &str, max_bytes: u64) -> ResultArtifactSpec {
        ResultArtifactSpec::try_new(
            name.to_owned(),
            max_bytes,
            Some("application/octet-stream".to_owned()),
        )
        .expect("valid test result declaration")
    }

    #[test]
    fn result_workspace_publishes_manifest_last_and_reopens_exact_bytes() {
        let root = tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let workspace =
            ResultWorkspace::prepare_exec(&jobs, Some("result-1"), &[spec("report.bin", 1024)])
                .expect("prepare")
                .expect("workspace");
        fs::write(workspace.incoming_path().join("report.bin"), b"payload").expect("child output");
        workspace.supervise().expect("supervise");
        let incoming = workspace.incoming_path().join("report.bin");
        let info = workspace.finalize().expect("finalize");
        // finalize is non-consuming. Windows refuses removal while the owner
        // still holds the root/incoming directory capability handles open.
        // Release the workspace just as the producing operation does before GC.
        drop(workspace);
        assert!(
            !incoming.exists(),
            "published payload should not retain a second child-writable copy"
        );
        assert_eq!(info.artifacts().len(), 1);
        assert_eq!(info.artifacts()[0].bytes(), 7);
        assert_eq!(
            info.artifacts()[0].sha256(),
            "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
        );
        let owner = ResultOwner::exec("result-1").expect("valid owner");
        let (artifact, mut file) =
            open_published(&jobs, &owner, "report.bin").expect("open published");
        assert_eq!(artifact, info.artifacts()[0]);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read");
        assert_eq!(bytes, b"payload");
        // Windows cannot remove the result tree while its published file is still open.
        drop(file);
        assert!(cleanup(&jobs, &owner).expect("cleanup"));
        assert!(!cleanup(&jobs, &owner).expect("already clean"));
    }

    #[test]
    fn result_cleanup_refuses_unpublished_active_workspace() {
        let root = tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let workspace =
            ResultWorkspace::prepare_exec(&jobs, Some("result-active"), &[spec("report.bin", 64)])
                .expect("prepare")
                .expect("workspace");
        fs::write(
            workspace.incoming_path().join("report.bin"),
            b"still-running",
        )
        .expect("child output");

        let owner = ResultOwner::exec("result-active").expect("valid owner");
        let error = cleanup(&jobs, &owner).expect_err("unpublished workspace must not be cleaned");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ),
            "{error:?}"
        );
        assert!(workspace.incoming_path().join("report.bin").is_file());
        workspace.discard().expect("discard");
    }

    #[test]
    fn result_workspace_rejects_undeclared_oversized_and_missing_outputs() {
        let root = tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let undeclared = ResultWorkspace::prepare_exec(
            &jobs,
            Some("result-undeclared"),
            &[spec("report.bin", 8)],
        )
        .expect("prepare")
        .expect("workspace");
        fs::write(undeclared.incoming_path().join("other.bin"), b"x").expect("other");
        assert!(undeclared.supervise().is_err());
        undeclared.discard().expect("discard");

        let oversized = ResultWorkspace::prepare_exec(
            &jobs,
            Some("result-oversized"),
            &[spec("report.bin", 3)],
        )
        .expect("prepare")
        .expect("workspace");
        fs::write(oversized.incoming_path().join("report.bin"), b"four").expect("oversized");
        assert!(oversized.supervise().is_err());
        oversized.discard().expect("discard");

        let missing =
            ResultWorkspace::prepare_exec(&jobs, Some("result-missing"), &[spec("report.bin", 3)])
                .expect("prepare")
                .expect("workspace");
        missing.supervise().expect("missing allowed while running");
        assert!(missing.finalize().is_err());
        missing.discard().expect("discard");
    }

    #[test]
    fn polling_is_best_effort_but_final_publication_rechecks_the_size_limit() {
        let root = tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let workspace =
            ResultWorkspace::prepare_exec(&jobs, Some("result-growth"), &[spec("report.bin", 4)])
                .expect("prepare")
                .expect("workspace");
        let output = workspace.incoming_path().join("report.bin");
        fs::write(&output, b"ok").expect("initial output");
        workspace.supervise().expect("within limit at poll time");
        fs::write(&output, b"grew beyond limit").expect("simulate growth between polls");

        assert!(workspace.finalize().is_err());
        assert!(!workspace.root_path.join(MANIFEST_FILE).exists());
        workspace.discard().expect("discard unpublished workspace");
    }

    #[test]
    fn exec_result_gc_removes_only_expired_owned_directories() {
        let root = tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let workspace =
            ResultWorkspace::prepare_exec(&jobs, Some("result-expired"), &[spec("report.bin", 64)])
                .expect("prepare")
                .expect("workspace");
        let root = workspace.root_path.clone();
        drop(workspace);
        let exec_root = jobs.join(EXEC_RESULTS_DIR);

        assert_eq!(EXEC_RESULT_RETENTION, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(
            gc_exec_result_sets_before(&exec_root, SystemTime::UNIX_EPOCH)
                .expect("retain recent set"),
            0
        );
        assert!(root.exists());
        assert_eq!(
            gc_exec_result_sets_before(&exec_root, SystemTime::now() + Duration::from_secs(2),)
                .expect("collect expired set"),
            1
        );
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn result_workspace_rejects_symlink_artifact_without_following() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("root");
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside").expect("outside");
        let jobs = root.path().join("jobs");
        let workspace =
            ResultWorkspace::prepare_exec(&jobs, Some("result-link"), &[spec("report.bin", 1024)])
                .expect("prepare")
                .expect("workspace");
        symlink(&outside, workspace.incoming_path().join("report.bin")).expect("symlink");
        assert!(workspace.supervise().is_err());
        workspace.discard().expect("discard");
        assert_eq!(fs::read(outside).expect("outside survives"), b"outside");
    }
}
