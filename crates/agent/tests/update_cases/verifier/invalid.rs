use super::*;

#[test]
fn fresh_package_verifier_rejects_unexpected_member() {
    let (temp, _root) = install_root();
    let version = env!("CARGO_PKG_VERSION");
    let archive = temp.path().join("unexpected-member.zip");
    let manifest = json!({
        "format": 1,
        "component": "agent",
        "target": TARGET,
        "version": version,
        "files": {"hostlink-agent": identity(b"unreached")},
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
    for (name, body) in [
        ("hostlink-agent", b"unreached".as_slice()),
        ("extra.txt", b"not part of the Agent".as_slice()),
        ("manifest.json", manifest_bytes.as_slice()),
    ] {
        zip.start_file(
            format!("hostlink-agent-{TARGET}/{name}"),
            SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(body).unwrap();
    }
    zip.finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&archive).unwrap()));
    let output = temp.path().join("unexpected-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(verify_fresh_package(&archive, &digest, TARGET, version, &output).is_err());
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
