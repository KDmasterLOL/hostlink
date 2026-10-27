use super::*;

fn record_fields() -> serde_json::Value {
    serde_json::json!({
        "format": 1,
        "owner_sid": "S-1-5-21-1000",
        "root": r"C:\Users\fixture\AppData\Local\HostLink\Agent",
        "executable": r"C:\Users\fixture\AppData\Local\HostLink\Agent\bin\hostlink-agent.exe",
        "executable_sha256": "a".repeat(64),
        "config": r"C:\Users\fixture\AppData\Local\HostLink\Agent\state\agent.json",
        "launcher_executable": r"C:\Windows\System32\wscript.exe",
        "startup_script": r"C:\Users\fixture\AppData\Local\HostLink\Agent\.hostlink-agent-start.vbs",
        "startup_script_sha256": "b".repeat(64),
        "pipe_name": r"\\.\pipe\hostlink-agent-fixture",
        "control_token": "c".repeat(64),
        "run_value": "hostlink-agent-fixture"
    })
}

#[test]
fn legacy_marker_defaults_to_normal_startup_and_maintenance_blocks_it() {
    let legacy: InstallRecord = serde_json::from_value(record_fields()).unwrap();
    assert!(!legacy.maintenance);
    assert!(legacy.maintenance_previous_sha256.is_none());
    assert!(refuse_maintenance(&legacy).is_ok());

    let mut pending = record_fields();
    pending["maintenance"] = serde_json::json!(true);
    pending["maintenance_previous_sha256"] = serde_json::json!("d".repeat(64));
    let pending: InstallRecord = serde_json::from_value(pending).unwrap();
    assert_eq!(
        refuse_maintenance(&pending).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn executable_digest_input_is_exact_lowercase_sha256() {
    assert!(validate_sha256(&"0".repeat(64)).is_ok());
    assert!(validate_sha256(&"A".repeat(64)).is_err());
    assert!(validate_sha256("short").is_err());
}

#[test]
fn maintenance_admission_is_bound_to_transaction_owner_root_and_candidate() {
    let mut fields = record_fields();
    fields["maintenance"] = serde_json::json!(true);
    fields["maintenance_previous_sha256"] = serde_json::json!("d".repeat(64));
    let record: InstallRecord = serde_json::from_value(fields).unwrap();
    let transaction = "e".repeat(64);
    let nonce = "f".repeat(64);
    let capability = format!("{transaction}{nonce}");
    let admission = MaintenanceAdmission {
        format: 1,
        transaction_id: transaction.clone(),
        root: record.root.clone(),
        owner_sid: record.owner_sid.clone(),
        executable_sha256: record.executable_sha256.clone(),
        capability_sha256: format!("{:x}", Sha256::digest(nonce.as_bytes())),
    };
    assert!(admission_matches(&admission, &record, &capability));
    assert!(!admission_matches(&admission, &record, ""));

    let stale_transaction = format!("{}{}", "a".repeat(64), nonce);
    assert!(!admission_matches(&admission, &record, &stale_transaction));
    assert!(!admission_matches(
        &admission,
        &record,
        &format!("{transaction}{}", "0".repeat(64))
    ));

    let mut wrong_root = record.clone();
    wrong_root.root.push("other");
    assert!(!admission_matches(&admission, &wrong_root, &capability));
    let mut wrong_sid = record.clone();
    wrong_sid.owner_sid.push_str("-2");
    assert!(!admission_matches(&admission, &wrong_sid, &capability));
    let mut wrong_executable = record.clone();
    wrong_executable.executable_sha256 = "9".repeat(64);
    assert!(!admission_matches(
        &admission,
        &wrong_executable,
        &capability
    ));

    let mut non_maintenance = record;
    non_maintenance.maintenance = false;
    assert!(!admission_matches(
        &admission,
        &non_maintenance,
        &capability
    ));
}

#[test]
fn concurrent_maintenance_admission_claims_have_one_winner() {
    use std::sync::{Arc, Barrier};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(MAINTENANCE_ADMISSION);
    write_private(&path, b"admission fixture").unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let claims: Vec<_> = (0..2)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let path = path.clone();
            std::thread::spawn(move || {
                let claim = open_maintenance_admission(&path);
                barrier.wait();
                claim.is_ok()
            })
        })
        .collect();
    assert_eq!(
        claims
            .into_iter()
            .map(|claim| claim.join().unwrap())
            .filter(|won| *won)
            .count(),
        1
    );
}

#[test]
fn consumed_maintenance_admission_cannot_be_reopened() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(MAINTENANCE_ADMISSION);
    write_private(&path, b"admission fixture").unwrap();
    let claim = open_maintenance_admission(&path).unwrap();
    fs::remove_file(&path).unwrap();
    drop(claim);
    assert_eq!(
        open_maintenance_admission(&path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn maintenance_admission_writer_does_not_replace_existing_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(MAINTENANCE_ADMISSION);
    fs::write(&path, b"existing admission state").unwrap();
    let error = write_maintenance_admission(&path, b"new admission state").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(path).unwrap(), b"existing admission state");
}

#[test]
fn maintenance_admission_cleanup_preserves_a_different_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(MAINTENANCE_ADMISSION);
    write_private(&path, b"different admission state").unwrap();
    assert!(remove_maintenance_admission(&path, b"issued admission state").is_err());
    assert_eq!(fs::read(path).unwrap(), b"different admission state");
}

#[test]
fn maintenance_admission_rejects_a_foreign_acl_entry() {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::SetNamedSecurityInfo;
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(MAINTENANCE_ADMISSION);
    write_private(&path, b"admission fixture").unwrap();
    let descriptor: LocalBox<SecurityDescriptor> = "D:P(A;;FA;;;WD)".parse().unwrap();
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(descriptor.dacl().unwrap()),
        None,
    )
    .unwrap();
    assert_eq!(
        open_maintenance_admission(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}
