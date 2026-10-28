//! Real offline CLI acceptance on disposable copied state; no service/network.

use hostlink_agent::durable::{DurableStore, JobId, JobRecord, JobSpec, JobState};
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path, process::Command};

fn private(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
    #[cfg(windows)]
    {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::{ConvertSidToStringSid, SetNamedSecurityInfo};
        use windows_permissions::{LocalBox, SecurityDescriptor};
        let sid = windows_permissions::utilities::current_process_sid().unwrap();
        let sid = ConvertSidToStringSid(&sid).unwrap();
        let flags = if directory { "OICI" } else { "" };
        let sddl = format!("D:P(A;{flags};FA;;;{})", sid.to_string_lossy());
        let descriptor: LocalBox<SecurityDescriptor> = sddl.parse().unwrap();
        SetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            descriptor.dacl(),
            None,
        )
        .unwrap();
    }
}

fn file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    private(path, false);
}

#[tokio::test]
async fn cli_verifies_copied_state_but_never_claims_a_successful_migration() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().canonicalize().unwrap();
    private(&parent, true);
    let root = parent.join("jobs");
    fs::create_dir(&root).unwrap();
    private(&root, true);
    file(&parent.join("update.lock"), b"");
    let stage = parent.join("stage");
    let spec = JobSpec {
        program: "do-not-launch-cli-test".into(),
        args: vec![],
        cwd: None,
        source_sha256: "a".repeat(64),
    };
    let record = JobRecord {
        version: 1,
        id: JobId::new(),
        controller_key_sha256: "b".repeat(64),
        request_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(&spec).unwrap())),
        spec,
        state: JobState::Exited { code: 23 },
    };
    let dir = root.join(record.id.to_string());
    fs::create_dir(&dir).unwrap();
    private(&dir, true);
    let raw = serde_json::to_vec_pretty(&record).unwrap();
    file(&dir.join("record.json"), &raw);
    file(&dir.join("state.lock"), b"");
    file(&dir.join("stdout.bin"), &[0, 255, 254, 13, 10, 0]);
    file(&dir.join("stderr.bin"), &[128, 0, 129]);

    for _ in 0..2 {
        let result = Command::new(env!("CARGO_BIN_EXE_hostlink-agent"))
            .args(["durable", "import-legacy", "--root"])
            .arg(&root)
            .arg("--stage")
            .arg(&stage)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(error.contains("verified snapshot stage"), "{error}");
        assert!(error.contains("publication blocked"), "{error}");
        assert!(!error.contains("do-not-launch-cli-test"));
        assert_eq!(fs::read(dir.join("record.json")).unwrap(), raw);
        assert_eq!(
            fs::read(dir.join("stdout.bin")).unwrap(),
            [0, 255, 254, 13, 10, 0]
        );
        assert!(!root.join("jobs.db").exists());
        assert!(DurableStore::open(stage.join("store")).await.is_err());
    }
}
