use super::*;

#[test]
fn fresh_package_verifier_rejects_duplicate_central_record_before_output() {
    let (temp, _root) = install_root();
    let sidecar = fs::read(env!("CARGO_BIN_EXE_hostlink-agent")).expect("read Agent sidecar");
    let version = env!("CARGO_PKG_VERSION");
    let (archive, _) = package(temp.path(), version, &sidecar);
    let archive_sha256 = duplicate_first_central_record(&archive, 1, 3);
    let output = temp.path().join("duplicate-central-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &archive_sha256, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_hidden_duplicate_after_declared_records() {
    let (temp, _root) = install_root();
    let sidecar = fs::read(env!("CARGO_BIN_EXE_hostlink-agent")).expect("read Agent sidecar");
    let version = env!("CARGO_PKG_VERSION");
    let (archive, _) = package(temp.path(), version, &sidecar);
    // Keep the canonical count of two while the central directory physically contains three.
    let archive_sha256 = duplicate_first_central_record(&archive, 1, 2);
    let output = temp.path().join("hidden-duplicate-central-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &archive_sha256, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_forged_central_record_count_before_output() {
    let (temp, _root) = install_root();
    let sidecar = fs::read(env!("CARGO_BIN_EXE_hostlink-agent")).expect("read Agent sidecar");
    let version = env!("CARGO_PKG_VERSION");
    let (archive, _) = package(temp.path(), version, &sidecar);
    // The fixture has two records; add four duplicate physical records but declare only five.
    let archive_sha256 = duplicate_first_central_record(&archive, 4, 5);
    let output = temp.path().join("forged-central-count-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &archive_sha256, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_wrong_source_target_and_sidecar_before_output() {
    let (temp, _root) = install_root();
    let executable = b"not the running verifier sidecar";
    let (archive, digest) = package(temp.path(), env!("CARGO_PKG_VERSION"), executable);
    let output = temp.path().join("rejected-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755))
            .expect("make output parent unsafe");
        assert!(
            verify_fresh_package(
                &archive,
                &digest,
                TARGET,
                env!("CARGO_PKG_VERSION"),
                &output
            )
            .is_err()
        );
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(
        verify_fresh_package(
            &archive,
            &"0".repeat(64),
            TARGET,
            env!("CARGO_PKG_VERSION"),
            &output
        )
        .is_err()
    );
    assert!(verify_fresh_package(&archive, &digest, TARGET, "99.0.0", &output).is_err());
    assert!(
        verify_fresh_package(
            &archive,
            &digest,
            "i686-win7-windows-msvc",
            env!("CARGO_PKG_VERSION"),
            &output
        )
        .is_err()
    );
    assert!(
        verify_fresh_package(
            &archive,
            &digest,
            TARGET,
            env!("CARGO_PKG_VERSION"),
            &output
        )
        .is_err()
    );
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_out_of_order_zip_members() {
    let (temp, _root) = install_root();
    let version = env!("CARGO_PKG_VERSION");
    let archive = temp.path().join("out-of-order.zip");
    let manifest = json!({
        "format": 1,
        "component": "agent",
        "target": TARGET,
        "version": version,
        "files": {"hostlink-agent": identity(b"unreached")},
    });
    let mut zip = zip::ZipWriter::new(File::create(&archive).expect("create archive"));
    zip.start_file(
        format!("hostlink-agent-{TARGET}/manifest.json"),
        SimpleFileOptions::default(),
    )
    .expect("start manifest first");
    zip.write_all(&serde_json::to_vec(&manifest).expect("manifest JSON"))
        .expect("write manifest");
    zip.start_file(
        format!("hostlink-agent-{TARGET}/hostlink-agent"),
        SimpleFileOptions::default(),
    )
    .expect("start executable second");
    zip.write_all(b"unreached").expect("write executable");
    zip.finish().expect("finish archive");
    let digest = format!(
        "{:x}",
        Sha256::digest(fs::read(&archive).expect("archive bytes"))
    );
    let output = temp.path().join("out-of-order-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &digest, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_duplicate_manifest_members() {
    let (temp, _root) = install_root();
    let version = env!("CARGO_PKG_VERSION");
    let executable = b"small invalid package executable";
    let identity = serde_json::to_string(&identity(executable)).expect("file identity");
    let manifest = format!(
        r#"{{"format":1,"component":"agent","target":"{TARGET}","version":"{version}","files":{{"hostlink-agent":{identity},"hostlink-agent":{identity}}}}}"#
    );
    let archive = temp.path().join("duplicate-manifest.zip");
    let mut zip = zip::ZipWriter::new(File::create(&archive).expect("create archive"));
    zip.start_file(
        format!("hostlink-agent-{TARGET}/hostlink-agent"),
        SimpleFileOptions::default(),
    )
    .expect("start executable");
    zip.write_all(executable).expect("write executable");
    zip.start_file(
        format!("hostlink-agent-{TARGET}/manifest.json"),
        SimpleFileOptions::default(),
    )
    .expect("start manifest");
    zip.write_all(manifest.as_bytes())
        .expect("write duplicate manifest");
    zip.finish().expect("finish archive");
    let archive_digest = format!("{:x}", Sha256::digest(fs::read(&archive).expect("archive")));
    let output = temp.path().join("duplicate-manifest-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &archive_digest, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn fresh_package_verifier_rejects_missing_required_member() {
    let (temp, _root) = install_root();
    let version = env!("CARGO_PKG_VERSION");
    let archive = temp.path().join("missing-member.zip");
    let manifest = json!({
        "format": 1,
        "component": "agent",
        "target": TARGET,
        "version": version,
        "files": {"hostlink-agent": identity(b"missing")},
    });
    let mut zip = zip::ZipWriter::new(File::create(&archive).expect("create archive"));
    zip.start_file(
        format!("hostlink-agent-{TARGET}/manifest.json"),
        SimpleFileOptions::default(),
    )
    .expect("start manifest");
    zip.write_all(&serde_json::to_vec(&manifest).expect("manifest JSON"))
        .expect("write manifest");
    zip.finish().expect("finish archive");
    let digest = format!("{:x}", Sha256::digest(fs::read(&archive).expect("archive")));
    let output = temp.path().join("missing-member-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    assert!(verify_fresh_package(&archive, &digest, TARGET, version, &output).is_err());
    assert!(!output.exists());
}
