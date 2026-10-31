#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use hostlink_agent::bootstrap::{finalize_fresh_install, verify_fresh_package};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

const TARGET: &str = "x86_64-unknown-linux-gnu";

fn identity(bytes: &[u8]) -> serde_json::Value {
    json!({"size": bytes.len(), "sha256": format!("{:x}", Sha256::digest(bytes))})
}

fn package(root: &Path, version: &str, executable: &[u8]) -> (PathBuf, String) {
    let files = BTreeMap::from([("hostlink-agent".to_owned(), identity(executable))]);
    let manifest = json!({
        "format": 2,
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
    (temp, root)
}

#[path = "bootstrap_cases/verifier/mod.rs"]
mod verifier;
