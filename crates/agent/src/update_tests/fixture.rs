use super::*;
use ::private_fs::PrivateDir;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn package(version: &str, exe: &[u8], symlink: bool) -> Vec<u8> {
    let files = crate::package::package_files(TARGET)
        .into_iter()
        .map(|name| {
            let bytes = if name.starts_with("hostlink-agent") {
                exe
            } else {
                b"disposable PS1"
            };
            (
                name,
                serde_json::json!({"size":bytes.len(),"sha256":digest(bytes)}),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let manifest = serde_json::json!({"format":2,"component":"agent","target":TARGET,"version":version,"files":files});
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for name in crate::package::package_files(TARGET) {
        let path = format!("hostlink-agent-{TARGET}/{name}");
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        if symlink && name.starts_with("hostlink-agent") {
            archive.add_symlink(path, "outside", options).unwrap();
        } else {
            archive.start_file(path, options).unwrap();
            archive
                .write_all(if name.starts_with("hostlink-agent") {
                    exe
                } else {
                    b"disposable PS1"
                })
                .unwrap();
        }
    }
    archive
        .start_file(
            format!("hostlink-agent-{TARGET}/manifest.json"),
            SimpleFileOptions::default(),
        )
        .unwrap();
    archive
        .write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();
    archive.finish().unwrap().into_inner()
}

pub(super) struct Fixture {
    pub temp: tempfile::TempDir,
    pub root: std::path::PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Agent");
        let private = PrivateDir::ensure(&root).unwrap();
        for name in ["jobs", "state", "keys"] {
            private.create_dir(name).unwrap();
        }
        for name in ["state/agent.json", "state/enrollment.json", "keys/host.key"] {
            private
                .create(name)
                .unwrap()
                .write_all(b"preserve private state")
                .unwrap();
        }
        let old = package("1.0.0", b"old executable", false);
        let archive = temp.path().join("old.zip");
        fs::write(&archive, &old).unwrap();
        let extracted = temp.path().join("extracted");
        self_update::Extract::from_source(&archive)
            .extract_into(&extracted)
            .unwrap();
        let bundle = extracted.join(format!("hostlink-agent-{TARGET}"));
        let (manifest, _) = crate::package::validate_contents(&archive, TARGET, "1.0.0").unwrap();
        fs::remove_file(bundle.join(PACKAGE_MANIFEST)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle.join(EXECUTABLE_BASE),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        fs::rename(bundle, root.join("bin")).unwrap();
        let metadata = crate::package::InstallMetadata {
            format: 2,
            target: TARGET.into(),
            installed_version: "1.0.0".into(),
            installed_package_sha256: digest(&old),
            installed_files: manifest.files,
        };
        fs::write(
            root.join("bin").join(INSTALL_METADATA),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        Self { temp, root }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn request(&self, url: &str, bytes: &[u8], version: &str) -> AgentUpdateRequest {
        AgentUpdateRequest {
            install_root: self.root.clone(),
            artifact: Artifact::loopback(url, digest(bytes), TARGET.into(), version.into())
                .unwrap(),
        }
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn preserved(&self) -> Vec<Vec<u8>> {
        ["state/agent.json", "state/enrollment.json", "keys/host.key"]
            .iter()
            .map(|name| fs::read(self.root.join(name)).unwrap())
            .collect()
    }
}
