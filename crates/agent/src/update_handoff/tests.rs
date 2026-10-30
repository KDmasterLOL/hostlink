//! Journal and recovery model regressions, including external behavior checks.

use super::*;

fn identity() -> UpdateIdentity {
    UpdateIdentity {
        target: "x86_64-win7-windows-msvc".into(),
        old_version: "1.0.0".into(),
        old_archive_sha256: "a".repeat(64),
        old_executable_sha256: "b".repeat(64),
        old_metadata_sha256: "c".repeat(64),
        new_version: "2.0.0".into(),
        new_archive_sha256: "d".repeat(64),
        new_executable_sha256: "e".repeat(64),
        new_metadata_sha256: "f".repeat(64),
    }
}

#[test]
fn journal_identity_is_deterministic_and_readback_rejects_tampering() {
    let first = UpdateJournal::new(identity()).expect("journal");
    let second = UpdateJournal::new(identity()).expect("journal");
    assert_eq!(first, second);
    first.validate().expect("valid journal");

    let mut changed = first;
    changed.identity.new_executable_sha256 = "1".repeat(64);
    assert!(changed.validate().is_err());
}

#[test]
fn journal_rejects_wrong_target_and_malformed_digest() {
    let mut wrong_target = identity();
    wrong_target.target = "x86_64-pc-windows-gnu".into();
    assert!(UpdateJournal::new(wrong_target).is_err());

    let mut wrong_digest = identity();
    wrong_digest.new_metadata_sha256 = "A".repeat(64);
    assert!(UpdateJournal::new(wrong_digest).is_err());
}

#[test]
fn legacy_live_update_journal_is_rejected() {
    let journal = UpdateJournal::new(identity()).unwrap();
    let mut value = serde_json::to_value(journal).unwrap();
    value["phase"] = serde_json::json!("RESTARTED");
    assert!(serde_json::from_value::<UpdateJournal>(value).is_err());
}

#[test]
fn transitions_are_linear_and_reject_skipped_phases() {
    let mut journal = UpdateJournal::new(identity()).expect("journal");
    assert!(journal.advance(UpdatePhase::Published).is_err());
    for phase in [
        UpdatePhase::BackedUp,
        UpdatePhase::Published,
        UpdatePhase::Verified,
    ] {
        journal.advance(phase).expect("valid forward phase");
    }
    journal
        .advance(UpdatePhase::RollingBack)
        .expect("verification failure may roll back before cleanup");
}

#[test]
fn rollback_transitions_are_explicit_and_terminal() {
    let mut journal = UpdateJournal::new(identity()).expect("journal");
    journal.advance(UpdatePhase::BackedUp).expect("backup");
    journal
        .advance(UpdatePhase::RollingBack)
        .expect("begin rollback");
    journal
        .advance(UpdatePhase::RolledBack)
        .expect("rollback complete");
    assert!(journal.advance(UpdatePhase::BackedUp).is_err());

    let mut verified = UpdateJournal::new(identity()).expect("journal");
    for phase in [
        UpdatePhase::BackedUp,
        UpdatePhase::Published,
        UpdatePhase::Verified,
    ] {
        verified.advance(phase).expect("advance to verified");
    }
    verified
        .advance(UpdatePhase::RollingBack)
        .expect("verified phase can enter rollback");
    verified
        .advance(UpdatePhase::RolledBack)
        .expect("rollback completes");
}

#[test]
fn crash_recovery_is_hash_and_phase_bound_and_fail_closed() {
    let old_and_stage = RecoveryEvidence {
        staged_new_valid: true,
        staged_new_metadata_valid: true,
        installed_old_valid: true,
        installed_old_metadata_valid: true,
        ..RecoveryEvidence::default()
    };
    assert_eq!(
        recovery_action(UpdatePhase::Staged, old_and_stage),
        RecoveryAction::CancelUnpublished
    );
    assert_eq!(
        recovery_action(UpdatePhase::Staged, RecoveryEvidence::default()),
        RecoveryAction::PreserveAndError
    );
    let new_and_backup = RecoveryEvidence {
        backup_old_valid: true,
        backup_old_metadata_valid: true,
        installed_new_valid: true,
        installed_new_metadata_valid: true,
        ..RecoveryEvidence::default()
    };
    assert_eq!(
        recovery_action(UpdatePhase::Published, new_and_backup),
        RecoveryAction::VerifyPublished
    );
    assert_eq!(
        recovery_action(
            UpdatePhase::Published,
            RecoveryEvidence {
                backup_old_valid: true,
                backup_old_metadata_valid: true,
                ..RecoveryEvidence::default()
            }
        ),
        RecoveryAction::PreserveAndError
    );
    assert_eq!(
        recovery_action(UpdatePhase::Verified, new_and_backup),
        RecoveryAction::CommitNew
    );
}

#[cfg(test)]
mod external_regressions {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    fn private_temp_dir() -> TempDir {
        let temp = TempDir::new().expect("temporary updater directory");
        fs::remove_dir(temp.path()).expect("remove empty temporary directory");
        private_fs::PrivateDir::ensure(temp.path()).expect("create private updater test fixture");
        temp
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn identity(old: &[u8], new: &[u8]) -> UpdateIdentity {
        UpdateIdentity {
            target: "x86_64-win7-windows-msvc".into(),
            old_version: "1.0.0".into(),
            old_archive_sha256: "a".repeat(64),
            old_executable_sha256: digest(old),
            old_metadata_sha256: digest(b"old install metadata"),
            new_version: "2.0.0".into(),
            new_archive_sha256: "c".repeat(64),
            new_executable_sha256: digest(new),
            new_metadata_sha256: digest(b"new install metadata"),
        }
    }

    #[test]
    fn persisted_journal_round_trips_and_corrupt_identity_is_rejected() {
        let temp = private_temp_dir();
        let path = temp.path().join("handoff.json");
        let journal = UpdateJournal::new(identity(b"old", b"new")).expect("valid journal");

        write_journal_atomic(&path, &journal).expect("persist initial phase");
        assert_eq!(read_journal(&path).expect("read journal"), Some(journal));

        let mut journal = UpdateJournal::new(identity(b"old", b"new")).expect("valid journal");
        journal
            .advance(UpdatePhase::BackedUp)
            .expect("advance phase");
        write_journal_atomic(&path, &journal).expect("atomically replace previous phase");
        assert_eq!(
            read_journal(&path).expect("read advanced journal"),
            Some(journal)
        );

        let mut bytes: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("journal bytes")).expect("journal JSON");
        bytes["identity"]["new_executable_sha256"] = serde_json::Value::String("e".repeat(64));
        fs::write(
            &path,
            serde_json::to_vec(&bytes).expect("tampered journal JSON"),
        )
        .expect("tamper journal");
        assert!(read_journal(&path).is_err());
    }

    #[test]
    fn file_hash_evidence_selects_recovery_and_rejects_wrong_installed_digest() {
        let temp = TempDir::new().expect("temporary updater directory");
        let staged = temp.path().join("staged.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let installed = temp.path().join("installed.exe");
        let installed_metadata = temp.path().join("install.json");
        let backup = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&staged, b"new executable").expect("staged executable");
        fs::write(&staged_metadata, b"new install metadata").expect("staged metadata");
        fs::write(&installed, b"new executable").expect("published executable");
        fs::write(&installed_metadata, b"new install metadata").expect("published metadata");
        fs::write(&backup, b"old executable").expect("backup executable");
        fs::write(&backup_metadata, b"old install metadata").expect("backup metadata");
        let identity = identity(b"old executable", b"new executable");
        let paths = TransactionFiles {
            staged_executable: &staged,
            staged_metadata: &staged_metadata,
            installed_executable: &installed,
            installed_metadata: &installed_metadata,
            backup_executable: &backup,
            backup_metadata: &backup_metadata,
        };

        let evidence = inspect_files(&paths, &identity).expect("hash transaction files");
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::VerifyPublished
        );

        // MoveAll can be interrupted after its executable move and before the metadata move.
        // BACKED_UP is durable before either move, so recovery restores the verified old pair.
        fs::write(&installed, b"new executable").expect("simulate swap before journal advance");
        fs::write(&installed_metadata, b"old install metadata").expect("metadata not swapped yet");
        let evidence = inspect_files(&paths, &identity).expect("observe interrupted first swap");
        assert_eq!(
            recovery_action(UpdatePhase::Staged, evidence),
            RecoveryAction::RestoreBackup
        );

        fs::write(&installed, b"unrecognized executable").expect("replace with wrong digest");
        let evidence = inspect_files(&paths, &identity).expect("hash mismatched files");
        assert!(!evidence.installed_old_valid);
        assert!(!evidence.installed_new_valid);
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::PreserveAndError
        );

        fs::write(&backup, b"wrong backup").expect("corrupt backup");
        let evidence = inspect_files(&paths, &identity).expect("hash corrupt backup");
        assert_eq!(
            recovery_action(UpdatePhase::Published, evidence),
            RecoveryAction::PreserveAndError
        );
    }

    #[cfg(unix)]
    #[test]
    fn recovery_hashing_rejects_symlink_candidates() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("temporary updater directory");
        let old = temp.path().join("old.exe");
        let new = temp.path().join("new.exe");
        let new_metadata = temp.path().join("new-install.json");
        let link = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&old, b"old").expect("old executable");
        fs::write(&new, b"new").expect("new executable");
        fs::write(&new_metadata, b"new install metadata").expect("new metadata");
        symlink(&old, &link).expect("backup symlink");
        fs::write(&backup_metadata, b"old install metadata").expect("backup metadata");
        let identity = identity(b"old", b"new");
        let paths = TransactionFiles {
            staged_executable: &new,
            staged_metadata: &new_metadata,
            installed_executable: &new,
            installed_metadata: &new_metadata,
            backup_executable: &link,
            backup_metadata: &backup_metadata,
        };
        assert!(inspect_files(&paths, &identity).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn offline_publish_failure_after_executable_swap_restores_exact_old_files() {
        let temp = private_temp_dir();
        let staged = temp.path().join("staged.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let installed = temp.path().join("hostlink-agent.exe");
        let installed_metadata = temp.path().join("install.json");
        let backup = temp.path().join("backup.exe");
        let backup_metadata = temp.path().join("backup-install.json");
        fs::write(&staged, b"new executable").expect("stage exact new executable");
        fs::write(&staged_metadata, b"new install metadata").expect("stage new metadata");
        fs::write(&installed, b"old executable").expect("installed old executable");
        fs::write(&installed_metadata, b"old install metadata").expect("installed old metadata");
        fs::copy(&installed, &backup).expect("durable old executable backup");
        fs::copy(&installed_metadata, &backup_metadata).expect("durable old metadata backup");

        let identity = identity(b"old executable", b"new executable");
        let journal = UpdateJournal::new(identity.clone()).expect("transaction identity");
        let journal_path = temp.path().join("handoff.json");
        write_journal_atomic(&journal_path, &journal).expect("durable STAGED journal");
        let files = TransactionFiles {
            staged_executable: &staged,
            staged_metadata: &staged_metadata,
            installed_executable: &installed,
            installed_metadata: &installed_metadata,
            backup_executable: &backup,
            backup_metadata: &backup_metadata,
        };
        let before = inspect_files(&files, &identity).expect("verify staged and backup evidence");
        assert_eq!(
            recovery_action(UpdatePhase::Staged, before),
            RecoveryAction::CancelUnpublished
        );

        // Inject a failure after the EXE replacement, before metadata publication or journal advance.
        fs::rename(&staged, &installed).expect("atomic executable swap");
        let interrupted =
            inspect_files(&files, &identity).expect("observe interrupted transaction");
        assert_eq!(
            recovery_action(UpdatePhase::BackedUp, interrupted),
            RecoveryAction::RestoreBackup
        );

        fs::copy(&backup, &installed).expect("rollback exact old executable");
        fs::write(
            &installed_metadata,
            fs::read(&backup_metadata).expect("backup bytes"),
        )
        .expect("rollback exact old metadata");
        let restored = inspect_files(&files, &identity).expect("verify rollback readback");
        assert!(restored.installed_old_valid);
        assert!(restored.installed_old_metadata_valid);
    }

    #[cfg(windows)]
    #[test]
    fn native_self_update_move_all_publishes_rolls_back_and_verifies_acl() {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::wrappers::{
            ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
        };

        fn sddl(path: &std::path::Path) -> String {
            let descriptor = GetNamedSecurityInfo(
                path.as_os_str(),
                SeObjectType::SE_FILE_OBJECT,
                SecurityInformation::Dacl | SecurityInformation::Owner,
            )
            .expect("read file security descriptor");
            ConvertSecurityDescriptorToStringSecurityDescriptor(
                &descriptor,
                SecurityInformation::Dacl | SecurityInformation::Owner,
            )
            .expect("format file security descriptor")
            .to_string_lossy()
            .into_owned()
        }

        let temp = TempDir::new().expect("disposable Windows update directory");
        let stash = temp.path().join("stash");
        fs::create_dir(&stash).expect("create same-volume stash");
        let installed = temp.path().join("hostlink-agent.exe");
        let installed_metadata = temp.path().join("install.json");
        let staged = temp.path().join("staged-agent.exe");
        let staged_metadata = temp.path().join("staged-install.json");
        let restore = temp.path().join("restore-agent.exe");
        let restore_metadata = temp.path().join("restore-install.json");
        fs::write(&installed, b"old executable").expect("write installed executable");
        fs::write(&installed_metadata, b"old metadata").expect("write installed metadata");
        fs::write(&staged, b"new executable").expect("write staged executable");
        fs::write(&staged_metadata, b"new metadata").expect("write staged metadata");
        let staged_acl = sddl(&staged);

        let mut publish = self_update::MoveAll::from_temp(&stash);
        publish
            .add(&staged, &installed)
            .add(&staged_metadata, &installed_metadata);
        publish.commit().expect("publish exact file pair");
        assert_eq!(
            fs::read(&installed).expect("read published image"),
            b"new executable"
        );
        assert_eq!(
            sddl(&installed),
            staged_acl,
            "published image retains the normalized private staging ACL"
        );

        fs::write(&restore, b"old executable").expect("write verified restore image");
        fs::write(&restore_metadata, b"old metadata").expect("write verified restore metadata");
        let rollback_stash = temp.path().join("rollback-stash");
        fs::create_dir(&rollback_stash).expect("create rollback stash");
        let mut rollback = self_update::MoveAll::from_temp(&rollback_stash);
        rollback
            .add(&restore, &installed)
            .add(&restore_metadata, &installed_metadata);
        rollback.commit().expect("restore exact prior file pair");
        assert_eq!(
            fs::read(&installed).expect("read restored image"),
            b"old executable"
        );
        assert_eq!(
            fs::read(&installed_metadata).expect("restored metadata"),
            b"old metadata"
        );

        let failed_first = temp.path().join("failed-first.exe");
        let failed_second = temp.path().join("missing-second.json");
        let failed_dest_first = temp.path().join("failed-dest-first.exe");
        let failed_dest_second = temp.path().join("failed-dest-second.json");
        fs::write(&failed_first, b"new first").expect("new first");
        fs::write(&failed_dest_first, b"old first").expect("old first");
        fs::write(&failed_dest_second, b"old second").expect("old second");
        let mut failing = self_update::MoveAll::from_temp(&stash);
        failing
            .add(&failed_first, &failed_dest_first)
            .add(&failed_second, &failed_dest_second);
        assert!(failing.commit().is_err(), "second source is absent");
        assert_eq!(
            fs::read(failed_dest_first).expect("first rollback"),
            b"old first"
        );
        assert_eq!(
            fs::read(failed_dest_second).expect("second rollback"),
            b"old second"
        );
    }
}
