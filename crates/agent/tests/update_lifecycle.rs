#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[path = "support/started_job.rs"]
mod started_job;

use hostlink_agent::jobs::JobStore;
use hostlink_agent::update::{
    AgentUpdateOutcome, AgentUpdateRequest, apply, finalize_fresh_install, verify_fresh_package,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn duplicate_first_central_record(path: &Path, copies: usize, declared_count: u16) -> String {
    let mut bytes = fs::read(path).expect("read package bytes");
    let eocd = bytes.len().checked_sub(22).expect("EOCD in fixture");
    let central_offset = usize::try_from(u32::from_le_bytes(
        bytes[eocd + 16..eocd + 20]
            .try_into()
            .expect("central directory offset"),
    ))
    .expect("central directory offset fits usize");
    let name_size = u16::from_le_bytes(
        bytes[central_offset + 28..central_offset + 30]
            .try_into()
            .expect("central name length"),
    );
    let name_size = usize::from(name_size);
    let extra_size = u16::from_le_bytes(
        bytes[central_offset + 30..central_offset + 32]
            .try_into()
            .expect("central extra length"),
    );
    let extra_size = usize::from(extra_size);
    let comment_size = u16::from_le_bytes(
        bytes[central_offset + 32..central_offset + 34]
            .try_into()
            .expect("central comment length"),
    );
    let comment_size = usize::from(comment_size);
    let first_record_size = 46 + name_size + extra_size + comment_size;
    let record = bytes[central_offset..central_offset + first_record_size].to_vec();
    let insertion = central_offset + first_record_size;
    for _ in 0..copies {
        bytes.splice(insertion..insertion, record.iter().copied());
    }
    let eocd = bytes
        .len()
        .checked_sub(22)
        .expect("EOCD in mutated fixture");
    bytes[eocd + 8..eocd + 10].copy_from_slice(&declared_count.to_le_bytes());
    bytes[eocd + 10..eocd + 12].copy_from_slice(&declared_count.to_le_bytes());
    let old_size = u32::from_le_bytes(
        bytes[eocd + 12..eocd + 16]
            .try_into()
            .expect("central directory size"),
    );
    let added_size = record
        .len()
        .checked_mul(copies)
        .and_then(|size| u32::try_from(size).ok())
        .expect("mutated central directory size fits u32");
    let new_size = old_size
        .checked_add(added_size)
        .expect("mutated central directory size does not overflow");
    bytes[eocd + 12..eocd + 16].copy_from_slice(&new_size.to_le_bytes());
    fs::write(path, &bytes).expect("write package with duplicated central record");
    format!("{:x}", Sha256::digest(&bytes))
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700))
            .expect("private bin directory");
    }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("install.json"), fs::Permissions::from_mode(0o600))
            .expect("private installed metadata");
    }
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
    // An installed Agent has an initialized durable database even when no
    // jobs were admitted. A missing database must not let the updater infer
    // that no active or interrupted operations existed.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let store = if jobs.join("jobs.db").try_exists()? {
            JobStore::open(&jobs).await?
        } else {
            JobStore::initialize_fresh(&jobs).await?
        };
        store.close().await;
        Ok::<(), io::Error>(())
    })?;
    apply(request)
}

#[path = "update_cases/publication.rs"]
mod publication;
#[path = "update_cases/recovery.rs"]
mod recovery;
#[path = "update_cases/rejections.rs"]
mod rejections;
#[path = "update_cases/verifier/mod.rs"]
mod verifier;
