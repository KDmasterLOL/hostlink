use super::jobs::verify_job_source;
use crate::durable::JobSpec;
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::PermissionsExt;

#[test]
fn job_source_rejects_digest_mismatch_and_symlink() {
    let temp = tempfile::tempdir().expect("private source fixture");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("protect source fixture");
    let source = temp.path().join("worker");
    std::fs::copy(std::env::current_exe().expect("test executable"), &source)
        .expect("copy source fixture");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500))
        .expect("make source immutable to group and others");
    let digest = format!(
        "{:x}",
        Sha256::digest(std::fs::read(&source).expect("source bytes"))
    );
    let mut spec = JobSpec {
        program: source.to_string_lossy().into_owned(),
        args: Vec::new(),
        cwd: None,
        source_sha256: "0".repeat(64),
    };
    assert!(
        verify_job_source(&spec).is_err(),
        "wrong pinned digest fails closed"
    );

    spec.source_sha256 = digest;
    let link = temp.path().join("worker-link");
    std::os::unix::fs::symlink(&source, &link).expect("create source symlink");
    spec.program = link.to_string_lossy().into_owned();
    assert!(
        verify_job_source(&spec).is_err(),
        "symlink source fails closed"
    );
}
