#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use hostlink_agent::jobs::{JobId, JobSpec, JobState, JobStore, active_ids};
use hostlink_agent::update::{AgentUpdateOutcome, AgentUpdateRequest, apply};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

const TARGET: &str = "x86_64-unknown-linux-gnu";

fn identity(bytes: &[u8]) -> serde_json::Value {
    json!({"size": bytes.len(), "sha256": format!("{:x}", Sha256::digest(bytes))})
}

fn request(root: &Path, archive: &Path, version: &str, digest: String) -> AgentUpdateRequest {
    AgentUpdateRequest {
        install_root: root.to_path_buf(),
        archive_file: archive.to_path_buf(),
        archive_sha256: digest,
        target: TARGET.to_owned(),
        version: version.to_owned(),
    }
}

fn package(root: &Path, version: &str, executable: &[u8]) -> (PathBuf, String) {
    let files = BTreeMap::from([("hostlink-agent".to_owned(), identity(executable))]);
    let manifest = json!({
        "format": 1,
        "component": "agent",
        "target": TARGET,
        "version": version,
        "files": files,
    });
    let entries = [
        ("hostlink-agent", executable.to_vec()),
        (
            "manifest.json",
            serde_json::to_vec(&manifest).expect("manifest JSON"),
        ),
    ];
    let path = root.join(format!("agent-{version}.zip"));
    let file = File::create(&path).expect("create archive");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        zip.start_file(format!("hostlink-agent-{TARGET}/{name}"), options)
            .expect("start ZIP member");
        zip.write_all(&bytes).expect("write ZIP member");
    }
    zip.finish().expect("finish archive");
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&path).expect("archive bytes"))
    );
    (path, digest)
}

fn malicious_archive(root: &Path, member: &str, symlink_member: bool) -> (PathBuf, String) {
    let executable = b"new exact Agent binary";
    let manifest = json!({
        "format": 1,
        "component": "agent",
        "target": TARGET,
        "version": "2.0.0",
        "files": {"hostlink-agent": identity(executable)},
    });
    let path = root.join("malicious.zip");
    let mut zip = zip::ZipWriter::new(File::create(&path).expect("create archive"));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(if symlink_member { 0o120777 } else { 0o100644 });
    zip.start_file(format!("hostlink-agent-{TARGET}/{member}"), options)
        .expect("start malicious member");
    zip.write_all(if symlink_member {
        b"target"
    } else {
        executable
    })
    .expect("write malicious member");
    zip.start_file(
        format!("hostlink-agent-{TARGET}/manifest.json"),
        SimpleFileOptions::default(),
    )
    .expect("start manifest");
    zip.write_all(&serde_json::to_vec(&manifest).expect("manifest"))
        .expect("write manifest");
    zip.finish().expect("finish archive");
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&path).expect("archive bytes"))
    );
    (path, digest)
}

fn install_root() -> (TempDir, PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix("hostlink-agent-test-")
        .tempdir()
        .expect("temp root");
    let root = temp.path().join("Agent");
    fs::create_dir(&root).expect("install root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    }
    let bin = root.join("bin");
    fs::create_dir(&bin).expect("bin directory");
    let old = b"old installed Agent binary";
    fs::write(bin.join("hostlink-agent"), old).expect("old binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            bin.join("hostlink-agent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("executable mode");
    }
    let metadata = json!({
        "format": 1,
        "target": TARGET,
        "installed_version": "1.0.0",
        "installed_package_sha256": "a".repeat(64),
        "installed_files": {"hostlink-agent": identity(old)},
    });
    fs::write(
        root.join("install.json"),
        serde_json::to_vec(&metadata).expect("install metadata"),
    )
    .expect("write install metadata");
    (temp, root)
}

fn apply_empty_jobs(request: &AgentUpdateRequest) -> io::Result<AgentUpdateOutcome> {
    let jobs = request.install_root.join("jobs");
    fs::create_dir_all(&jobs)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700))?;
    }
    apply(request)
}

#[test]
fn active_job_blocks_update_despite_unrelated_empty_jobs_directory() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    let unrelated_empty_jobs = root.join("unrelated-empty-jobs");
    fs::create_dir(&unrelated_empty_jobs).expect("unrelated empty jobs directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
        fs::set_permissions(&unrelated_empty_jobs, fs::Permissions::from_mode(0o700))
            .expect("private unrelated jobs directory");
    }
    let store = JobStore::open(&jobs).expect("job store");
    let id = JobId::new();
    let owner = "1".repeat(64);
    store
        .admit(
            id,
            &owner,
            &JobSpec {
                program: "true".to_owned(),
                args: Vec::new(),
                cwd: None,
                source_sha256: "2".repeat(64),
            },
        )
        .expect("admit prepared job");

    let update = request(&root, &archive, "2.0.0", digest);
    assert!(
        fs::read_dir(&unrelated_empty_jobs)
            .expect("unrelated empty jobs directory")
            .next()
            .is_none()
    );
    assert_eq!(
        apply(&update).expect("defer update"),
        AgentUpdateOutcome::DeferredActiveJobs {
            job_ids: vec![id.to_string()],
        }
    );
    assert_eq!(
        active_ids(&jobs).expect("job stays active"),
        vec![id.to_string()]
    );
    store
        .transition(id, &owner, JobState::Prepared, JobState::Running)
        .expect("job is running");
    assert!(matches!(
        apply(&update).expect("running job defers update"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.to_string()]
    ));
    store
        .transition(id, &owner, JobState::Running, JobState::Interrupted)
        .expect("job is interrupted");
    assert!(matches!(
        apply(&update).expect("interrupted job defers update"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.to_string()]
    ));
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}

#[test]
fn unknown_job_store_entry_fails_closed() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
    }
    fs::write(jobs.join("not-a-job-record"), b"unknown state").expect("unknown entry");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(apply(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}

#[test]
fn active_job_prevents_recovery_mutations_then_update_recovers_backup() {
    let (_temp, root) = install_root();
    let old_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("old metadata"))
            .expect("valid old metadata");
    let backup_name = format!("backup-1.0.0-{}", "a".repeat(64));
    let updates = root.join(".updates");
    fs::create_dir(&updates).expect("updates directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&updates, fs::Permissions::from_mode(0o700))
            .expect("private updates directory");
    }
    let backup = updates.join(&backup_name);
    fs::rename(root.join("bin"), &backup).expect("simulate interrupted rename");
    fs::write(
        updates.join("publication.json"),
        serde_json::to_vec(&json!({
            "format": 1,
            "backup": backup_name,
            "old_metadata": old_metadata,
        }))
        .expect("journal JSON"),
    )
    .expect("write recovery journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            updates.join("publication.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private recovery journal");
    }

    let jobs = root.join("jobs");
    fs::create_dir(&jobs).expect("jobs root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&jobs, fs::Permissions::from_mode(0o700)).expect("private jobs root");
    }
    let store = JobStore::open(&jobs).expect("job store");
    let id = JobId::new();
    let owner = "1".repeat(64);
    store
        .admit(
            id,
            &owner,
            &JobSpec {
                program: "true".to_owned(),
                args: Vec::new(),
                cwd: None,
                source_sha256: "2".repeat(64),
            },
        )
        .expect("admit active job");
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(matches!(
        apply(&update).expect("defer while recovery is pending"),
        AgentUpdateOutcome::DeferredActiveJobs { job_ids } if job_ids == vec![id.to_string()]
    ));
    assert!(!root.join("bin").exists());
    assert!(backup.join("hostlink-agent").is_file());

    store
        .transition(id, &owner, JobState::Prepared, JobState::Failed)
        .expect("job reaches terminal state");
    assert!(matches!(
        apply(&update).expect("recover and update"),
        AgentUpdateOutcome::Installed { .. }
    ));
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("updated binary"),
        b"new exact Agent binary"
    );
}

#[test]
fn recovery_restores_old_install_after_simulated_interrupted_publication() {
    let (_temp, root) = install_root();
    let old_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("old metadata"))
            .expect("valid old metadata");
    let backup_name = format!("backup-1.0.0-{}", "a".repeat(64));
    let updates = root.join(".updates");
    fs::create_dir(&updates).expect("updates directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&updates, fs::Permissions::from_mode(0o700))
            .expect("private updates directory");
    }
    let backup = updates.join(&backup_name);
    fs::rename(root.join("bin"), &backup).expect("simulate crash after backup rename");
    let journal = updates.join("publication.json");
    fs::write(
        &journal,
        serde_json::to_vec(&json!({
            "format": 1,
            "backup": backup_name,
            "old_metadata": old_metadata,
        }))
        .expect("journal JSON"),
    )
    .expect("write recovery journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))
            .expect("private recovery journal");
    }

    let (archive, _) = package(&root, "2.0.0", b"new exact Agent binary");
    let bad_digest = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&bad_digest).is_err());

    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("restored old executable"),
        b"old installed Agent binary"
    );
    let restored_metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("install.json")).expect("restored metadata"))
            .expect("valid restored metadata");
    assert_eq!(restored_metadata, old_metadata);
    assert!(!backup.exists());
    assert!(!journal.exists());
}

#[test]
fn exact_package_updates_files_and_repeat_is_idempotent() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let request = request(&root, &archive, "2.0.0", digest.clone());

    assert_eq!(
        apply_empty_jobs(&request).expect("install package"),
        AgentUpdateOutcome::Installed {
            version: "2.0.0".to_owned(),
            archive_sha256: digest.clone(),
        }
    );
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("installed binary"),
        b"new exact Agent binary"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("bin/hostlink-agent"))
            .expect("installed metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o100, 0);
        assert_eq!(mode & 0o022, 0, "group/world write bits must be clear");
    }
    assert_eq!(
        apply_empty_jobs(&request).expect("idempotent repeat"),
        AgentUpdateOutcome::AlreadyCurrent {
            version: "2.0.0".to_owned(),
            archive_sha256: digest,
        }
    );
}

#[cfg(unix)]
#[test]
fn unsafe_executable_permissions_block_update() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let executable = root.join("bin/hostlink-agent");

    for unsafe_mode in [0o471, 0o722] {
        fs::set_permissions(&executable, fs::Permissions::from_mode(unsafe_mode))
            .expect("set unsafe executable permissions");
        let update = request(&root, &archive, "2.0.0", digest.clone());
        assert!(apply_empty_jobs(&update).is_err());
        assert_eq!(
            fs::read(&executable).expect("original executable remains"),
            b"old installed Agent binary"
        );
        assert_eq!(
            fs::metadata(&executable)
                .expect("executable metadata")
                .permissions()
                .mode()
                & 0o777,
            unsafe_mode
        );
    }
}

#[test]
fn wrong_digest_and_wrong_target_fail_before_publication() {
    let (_temp, root) = install_root();
    let (archive, _) = package(&root, "2.0.0", b"new exact Agent binary");
    let before = fs::read(root.join("bin/hostlink-agent")).expect("old binary");
    let bad_digest = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&bad_digest).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary remains"),
        before
    );

    let mut wrong_target = request(&root, &archive, "2.0.0", "0".repeat(64));
    wrong_target.target = "i686-win7-windows-msvc".to_owned();
    assert!(apply_empty_jobs(&wrong_target).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary remains"),
        before
    );
}

#[cfg(unix)]
#[test]
fn symlinked_archive_is_rejected_without_changes() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = install_root();
    let (outside_temp, outside_root) = install_root();
    let (outside, digest) = package(&outside_root, "2.0.0", b"new exact Agent binary");
    let linked = root.join("linked.zip");
    symlink(outside, &linked).expect("archive symlink");
    let request = request(&root, &linked, "2.0.0", digest);
    assert!(apply_empty_jobs(&request).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary"),
        b"old installed Agent binary"
    );
    drop(outside_temp);
}

#[test]
fn archive_manifest_must_bind_exact_version_and_target() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let mut request = request(&root, &archive, "2.1.0", digest);
    assert!(apply_empty_jobs(&request).is_err());
    request.version = "invalid".to_owned();
    assert!(apply_empty_jobs(&request).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("old binary"),
        b"old installed Agent binary"
    );
}

#[test]
fn zip_slip_and_symlink_members_are_rejected() {
    let (_temp, root) = install_root();
    for (member, symlink) in [("../escape", false), ("hostlink-agent", true)] {
        let (archive, digest) = malicious_archive(&root, member, symlink);
        let update = request(&root, &archive, "2.0.0", digest);
        assert!(apply_empty_jobs(&update).is_err());
        assert_eq!(
            fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
            b"old installed Agent binary"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinked_install_root_is_rejected() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    let alias = root.with_file_name("Agent-alias");
    symlink(&root, &alias).expect("install root symlink");
    let update = request(&alias, &archive, "2.0.0", digest);
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}

#[test]
fn tampered_installed_binary_blocks_update() {
    let (_temp, root) = install_root();
    let (archive, digest) = package(&root, "2.0.0", b"new exact Agent binary");
    fs::write(root.join("bin/hostlink-agent"), b"tampered").expect("tamper binary");
    let update = request(&root, &archive, "2.0.0", digest);
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("tampered binary remains untouched"),
        b"tampered"
    );
}

#[test]
fn oversized_archive_is_rejected_before_copy_or_publication() {
    let (_temp, root) = install_root();
    let archive = root.join("oversized.zip");
    let file = File::create(&archive).expect("sparse oversized archive");
    file.set_len(512 * 1024 * 1024 + 1)
        .expect("set oversized archive length");
    let update = request(&root, &archive, "2.0.0", "0".repeat(64));
    assert!(apply_empty_jobs(&update).is_err());
    assert_eq!(
        fs::read(root.join("bin/hostlink-agent")).expect("original binary"),
        b"old installed Agent binary"
    );
}
