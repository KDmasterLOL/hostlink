use super::*;
use std::os::unix::fs::PermissionsExt;

pub(super) async fn fixture() -> (tempfile::TempDir, JobStore, String, JobSpec) {
    let temp = tempfile::tempdir().unwrap();
    restrict_private_path(temp.path(), true).unwrap();
    let install = temp.path().join("install");
    fs::create_dir(&install).unwrap();
    restrict_private_path(&install, true).unwrap();
    let root = install.join("jobs");
    fs::create_dir(&root).unwrap();
    restrict_private_path(&root, true).unwrap();
    let store = JobStore::initialize_fresh(root).await.unwrap();
    let owner = "a".repeat(64);
    let artifacts = store.artifacts(&owner).unwrap();
    let bytes = b"#!/bin/sh\nexit 0\n";
    let digest = format!("{:x}", Sha256::digest(bytes));
    let name = format!("{digest}.upload");
    let upload = artifacts.upload_root().join(&name);
    fs::write(&upload, bytes).unwrap();
    restrict_private_path(&upload, false).unwrap();
    let program = artifacts.seal(&name, &digest, bytes.len() as u64).unwrap();
    let spec = JobSpec {
        program: program.to_str().unwrap().into(),
        args: vec![],
        cwd: None,
        source_sha256: digest,
    };
    (temp, store, owner, spec)
}

#[tokio::test]
async fn unsafe_ancestor_above_install_rejects_source_open_and_seal() {
    let (temp, store, owner, spec) = fixture().await;
    let artifacts = store.artifacts(&owner).unwrap();
    let name = format!("{}.upload", spec.source_sha256);
    let size = fs::metadata(&spec.program).unwrap().len();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(verify_job_source(&store, &owner, &spec).is_err());
    assert!(
        artifacts
            .authorize_source(&spec.program, &spec.source_sha256)
            .is_err()
    );
    assert!(artifacts.seal(&name, &spec.source_sha256, size).is_err());
    restrict_private_path(temp.path(), true).unwrap();
    verify_job_source(&store, &owner, &spec).unwrap();

    let aliases = tempfile::tempdir().unwrap();
    let link = aliases.path().join("outer-alias");
    std::os::unix::fs::symlink(temp.path(), &link).unwrap();
    assert!(ArtifactStore::open(&link.join("install/jobs"), &owner).is_err());
}

#[tokio::test]
async fn only_exact_owned_sealed_source_is_authorized() {
    let (temp, store, owner, spec) = fixture().await;
    verify_job_source(&store, &owner, &spec).unwrap();
    // The same digest in another controller's store grants no source access.
    let other = "b".repeat(64);
    let artifacts = store.artifacts(&other).unwrap();
    let name = format!("{}.upload", spec.source_sha256);
    let bytes = fs::read(&spec.program).unwrap();
    let upload = artifacts.upload_root().join(&name);
    fs::write(&upload, &bytes).unwrap();
    restrict_private_path(&upload, false).unwrap();
    artifacts
        .seal(&name, &spec.source_sha256, bytes.len() as u64)
        .unwrap();
    assert!(verify_job_source(&store, &other, &spec).is_err());

    let parent = temp.path().join("foreign-writable");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    let arbitrary = parent.join(format!("{}.program", spec.source_sha256));
    fs::copy(&spec.program, &arbitrary).unwrap();
    let mut bad = spec.clone();
    bad.program = arbitrary.to_str().unwrap().into();
    assert!(verify_job_source(&store, &owner, &bad).is_err());

    let program = Path::new(&spec.program);
    let sealed = program.parent().unwrap();
    let link = temp.path().join("alias");
    std::os::unix::fs::symlink(sealed, &link).unwrap();
    let file_link = temp.path().join("program-link");
    std::os::unix::fs::symlink(program, &file_link).unwrap();
    for alias in [
        file_link,
        link.join(program.file_name().unwrap()),
        sealed
            .join("..")
            .join("sealed")
            .join(program.file_name().unwrap()),
        sealed.join(".").join(program.file_name().unwrap()),
    ] {
        bad.program = alias.to_str().unwrap().into();
        assert!(
            verify_job_source(&store, &owner, &bad).is_err(),
            "alias: {}",
            bad.program
        );
    }
    fs::set_permissions(sealed, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(verify_job_source(&store, &owner, &spec).is_err());
    restrict_private_path(sealed, true).unwrap();
    verify_job_source(&store, &owner, &spec).unwrap();

    // A symlink replacing the expected sealed filename is unsafe as well,
    // even when it resolves to the original correctly hashed private file.
    let original = temp.path().join("original-program");
    fs::rename(program, &original).unwrap();
    std::os::unix::fs::symlink(&original, program).unwrap();
    assert!(verify_job_source(&store, &owner, &spec).is_err());
    fs::remove_file(program).unwrap();
    fs::rename(&original, program).unwrap();
    verify_job_source(&store, &owner, &spec).unwrap();
}

#[tokio::test]
async fn job_source_rejects_writable_file_digest_corruption_and_unsafe_cwd() {
    let (temp, store, owner, spec) = fixture().await;
    fs::set_permissions(&spec.program, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(verify_job_source(&store, &owner, &spec).is_err());
    fs::write(&spec.program, b"corrupted executable").unwrap();
    fs::set_permissions(&spec.program, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(verify_job_source(&store, &owner, &spec).is_err());

    // Restore sealed bytes to isolate cwd validation from the digest gate.
    fs::set_permissions(&spec.program, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&spec.program, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&spec.program, fs::Permissions::from_mode(0o500)).unwrap();
    let mut bad = spec.clone();
    bad.cwd = Some(temp.path().to_path_buf());
    verify_job_source(&store, &owner, &bad).unwrap();
    let link = temp.path().join("cwd-link");
    std::os::unix::fs::symlink(temp.path(), &link).unwrap();
    for cwd in [
        link,
        PathBuf::from("relative"),
        PathBuf::from(&spec.program),
    ] {
        bad.cwd = Some(cwd);
        assert!(verify_job_source(&store, &owner, &bad).is_err());
    }
}
