use super::*;

#[test]
fn fresh_package_verifier_extracts_exact_manifest_and_installed_metadata() {
    let (temp, _root) = install_root();
    let source_sidecar = PathBuf::from(env!("CARGO_BIN_EXE_hostlink-agent"));
    let sidecar = fs::read(&source_sidecar).expect("read target Agent sidecar bytes");
    // Cargo may atomically replace its target executable during another check.
    // Run this exact private snapshot so current_exe remains the packaged source.
    let sidecar_path = temp.path().join("verifier-sidecar");
    fs::write(&sidecar_path, &sidecar).expect("stage exact private verifier sidecar");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sidecar_path, fs::Permissions::from_mode(0o500))
            .expect("private read-only verifier sidecar");
    }
    let version = env!("CARGO_PKG_VERSION");
    let files = BTreeMap::from([("hostlink-agent".to_owned(), identity(&sidecar))]);
    let manifest = json!({
        "format": 2,
        "component": "agent",
        "target": TARGET,
        "version": version,
        "files": files,
    });
    let archive = temp.path().join("fresh-package.zip");
    let mut zip = zip::ZipWriter::new(File::create(&archive).expect("create archive"));
    // Verify that the safe package contract is independent of ZIP member order.
    zip.start_file(
        format!("hostlink-agent-{TARGET}/manifest.json"),
        SimpleFileOptions::default(),
    )
    .expect("start manifest member");
    zip.write_all(&serde_json::to_vec(&manifest).expect("manifest JSON"))
        .expect("write manifest");
    zip.start_file(
        format!("hostlink-agent-{TARGET}/hostlink-agent"),
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
    )
    .expect("start executable member");
    zip.write_all(&sidecar).expect("write executable");
    zip.finish().expect("finish archive");
    let archive_sha256 = format!("{:x}", Sha256::digest(fs::read(&archive).expect("archive")));
    let output = temp.path().join("fresh-stage");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private output parent");
    }

    let verification = Command::new(&sidecar_path)
        .args([
            "bootstrap-verify",
            "--archive",
            archive.to_str().expect("archive path UTF-8"),
            "--sha256",
            &archive_sha256,
            "--target",
            TARGET,
            "--version",
            version,
            "--output",
            output.to_str().expect("output path UTF-8"),
        ])
        .output()
        .expect("run target Agent verifier sidecar");
    assert!(
        verification.status.success(),
        "sidecar rejected the authentic exact package: {}",
        String::from_utf8_lossy(&verification.stderr)
    );
    assert!(String::from_utf8_lossy(&verification.stdout).contains(&archive_sha256));

    assert_eq!(
        fs::read(output.join("hostlink-agent")).expect("extracted sidecar"),
        sidecar
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("install.json")).expect("metadata"))
            .expect("metadata JSON");
    assert_eq!(metadata["format"], 2);
    assert_eq!(metadata["target"], TARGET);
    assert_eq!(metadata["installed_version"], version);
    assert_eq!(metadata["installed_package_sha256"], archive_sha256);
    assert_eq!(
        metadata["installed_files"]["hostlink-agent"]["sha256"],
        format!("{:x}", Sha256::digest(&sidecar))
    );

    let root = temp.path().join("installed-agent");
    fs::create_dir(&root).expect("fresh root");
    let state = root.join("state");
    let bin = root.join("bin");
    fs::create_dir(&state).expect("state directory");
    fs::create_dir(&bin).expect("bin directory");
    fs::write(state.join("agent.json"), b"validated enrollment config").expect("config");
    fs::write(
        root.join("enrollment.pending"),
        b"reconcile until installer completes\n",
    )
    .expect("pending marker");
    fs::copy(output.join("hostlink-agent"), bin.join("hostlink-agent"))
        .expect("publish verified executable");
    fs::copy(output.join("install.json"), root.join("bin/install.json"))
        .expect("publish install metadata");
    assert!(!root.join("install.json").exists());
    fs::copy(
        output.join("bootstrap-receipt.json"),
        root.join("bootstrap-receipt.json"),
    )
    .expect("publish source receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("private state");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).expect("private bin");
        fs::set_permissions(
            bin.join("hostlink-agent"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private executable");
        fs::set_permissions(state.join("agent.json"), fs::Permissions::from_mode(0o600))
            .expect("private config");
        fs::set_permissions(
            root.join("bin/install.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private metadata");
        fs::set_permissions(
            root.join("bootstrap-receipt.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private receipt");
        fs::set_permissions(
            root.join("enrollment.pending"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private pending marker");
    }
    fs::write(root.join("bootstrap-receipt.json"), b"{}").expect("tamper with source receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join("bootstrap-receipt.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("keep tampered receipt private");
    }
    assert!(finalize_fresh_install(&root).is_err());
    assert!(root.join("enrollment.pending").is_file());
    fs::copy(
        output.join("bootstrap-receipt.json"),
        root.join("bootstrap-receipt.json"),
    )
    .expect("restore verified source receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join("bootstrap-receipt.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restore private receipt permissions");
    }
    finalize_fresh_install(&root).expect("finalize exact package install");
    assert!(!root.join("enrollment.pending").exists());
    assert!(verify_fresh_package(&archive, &archive_sha256, TARGET, version, &output).is_err());
}
