//! Windows-only recovery regressions retained with the Windows implementation.

#[cfg(windows)]
mod windows_recovery_tests {
    use crate::update::{
        INSTALL_METADATA,
        manifest::{FileIdentity, InstallMetadata},
        windows::{
            fs::{create_private_directory, write_private_synced},
            recovery::recover_windows_handoff,
        },
    };
    use crate::update_handoff::{UpdateIdentity, UpdateJournal, UpdatePhase, write_journal_atomic};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, fs, path::PathBuf};
    use tempfile::TempDir;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn standard_library_directory_handle_preserves_file_identity() {
        use crate::update::windows::fs::windows_file_identity;
        let root = TempDir::new().unwrap();
        let directory = root.path().join("directory");
        private_fs::PrivateDir::ensure(&directory).unwrap();
        let (volume, index) = windows_file_identity(&directory, true).unwrap();
        assert_ne!(index, 0);
        assert_eq!(
            (volume, index),
            windows_file_identity(&directory.join("."), true).unwrap()
        );
        let file = directory.join("file");
        write_private_synced(&file, b"not a directory").unwrap();
        assert_ne!(
            (volume, index),
            windows_file_identity(&file, false).unwrap()
        );
    }

    struct Fixture {
        _temp: TempDir,
        root: PathBuf,
        transaction: PathBuf,
        journal: PathBuf,
        old_exe: Vec<u8>,
        new_exe: Vec<u8>,
        old_metadata: Vec<u8>,
        new_metadata: Vec<u8>,
    }

    impl Fixture {
        fn new(phase: UpdatePhase, publish_new_exe: bool, publish_new_metadata: bool) -> Self {
            let temp = TempDir::new().expect("disposable Windows recovery root");
            let root = temp.path().join("agent");
            private_fs::PrivateDir::ensure(&root).expect("private recovery root at birth");
            let updates = root.join(".updates");
            let bin = root.join("bin");
            create_private_directory(&updates).expect("private updates directory");
            create_private_directory(&bin).expect("private installed bin directory");

            let old_exe = b"old disposable agent image".to_vec();
            let new_exe = b"new disposable agent image".to_vec();
            let support = [
                ("Install-HostLink-Agent.ps1", b"install support".as_slice()),
                ("Run-HostLink-Agent.ps1", b"run support".as_slice()),
                ("Update-HostLink-Agent.ps1", b"update support".as_slice()),
            ];
            for (name, bytes) in support {
                write_private_synced(&bin.join(name), bytes).expect("private support file");
            }
            let old_files = package_file_map(&old_exe, &support);
            let new_files = package_file_map(&new_exe, &support);
            let old_metadata = serde_json::to_vec_pretty(&InstallMetadata {
                format: 1,
                target: "x86_64-win7-windows-msvc".into(),
                installed_version: "1.0.0".into(),
                installed_package_sha256: "a".repeat(64),
                installed_files: old_files,
            })
            .expect("old metadata bytes");
            let new_metadata = serde_json::to_vec_pretty(&InstallMetadata {
                format: 1,
                target: "x86_64-win7-windows-msvc".into(),
                installed_version: "2.0.0".into(),
                installed_package_sha256: "c".repeat(64),
                installed_files: new_files,
            })
            .expect("new metadata bytes");
            write_private_synced(
                &bin.join("hostlink-agent.exe"),
                if publish_new_exe { &new_exe } else { &old_exe },
            )
            .expect("installed executable");
            write_private_synced(
                &root.join(INSTALL_METADATA),
                if publish_new_metadata {
                    &new_metadata
                } else {
                    &old_metadata
                },
            )
            .expect("installed metadata");

            let identity = UpdateIdentity {
                target: "x86_64-win7-windows-msvc".into(),
                old_version: "1.0.0".into(),
                old_archive_sha256: "a".repeat(64),
                old_executable_sha256: digest(&old_exe),
                old_metadata_sha256: digest(&old_metadata),
                new_version: "2.0.0".into(),
                new_archive_sha256: "c".repeat(64),
                new_executable_sha256: digest(&new_exe),
                new_metadata_sha256: digest(&new_metadata),
            };
            let mut journal = UpdateJournal::new(identity.clone()).expect("journal identity");
            let transaction = updates.join(format!("transaction-{}", journal.transaction_id()));
            create_private_directory(&transaction).expect("private transaction directory");
            if phase != UpdatePhase::Staged {
                journal
                    .advance(UpdatePhase::BackedUp)
                    .expect("backed up phase");
            }
            if matches!(phase, UpdatePhase::Published | UpdatePhase::Verified) {
                journal
                    .advance(UpdatePhase::Published)
                    .expect("published phase");
            }
            if matches!(phase, UpdatePhase::Verified) {
                journal
                    .advance(UpdatePhase::Verified)
                    .expect("verified phase");
            }
            for (name, bytes) in [
                ("staged-agent.exe", new_exe.as_slice()),
                ("staged-install.json", new_metadata.as_slice()),
                ("backup-agent.exe", old_exe.as_slice()),
                ("backup-install.json", old_metadata.as_slice()),
            ] {
                write_private_synced(&transaction.join(name), bytes).expect("transaction file");
            }
            let journal_path = updates.join("handoff.json");
            write_journal_atomic(&journal_path, &journal).expect("persist fixture journal");
            Self {
                _temp: temp,
                root,
                transaction,
                journal: journal_path,
                old_exe,
                new_exe,
                old_metadata,
                new_metadata,
            }
        }
    }

    fn package_file_map(
        executable: &[u8],
        support: &[(&str, &[u8]); 3],
    ) -> BTreeMap<String, FileIdentity> {
        let mut files = BTreeMap::new();
        files.insert(
            "hostlink-agent.exe".into(),
            FileIdentity {
                size: executable.len() as u64,
                sha256: digest(executable),
            },
        );
        for (name, bytes) in support {
            files.insert(
                (*name).to_owned(),
                FileIdentity {
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                },
            );
        }
        files
    }

    #[test]
    fn recovery_restores_backed_up_transaction_and_is_idempotent() {
        let fixture = Fixture::new(UpdatePhase::BackedUp, true, false);
        recover_windows_handoff(&fixture.root).expect("restore old installation");
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            fixture.old_exe
        );
        assert_eq!(
            fs::read(fixture.root.join(INSTALL_METADATA)).unwrap(),
            fixture.old_metadata
        );
        assert!(!fixture.journal.exists());
        assert!(!fixture.transaction.exists());
        recover_windows_handoff(&fixture.root).expect("second recovery is a no-op");
    }

    #[test]
    fn recovery_commits_published_complete_manifest() {
        let fixture = Fixture::new(UpdatePhase::Published, true, true);
        recover_windows_handoff(&fixture.root).expect("validate and commit new install");
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            fixture.new_exe
        );
        assert_eq!(
            fs::read(fixture.root.join(INSTALL_METADATA)).unwrap(),
            fixture.new_metadata
        );
        assert!(!fixture.journal.exists());
        assert!(!fixture.transaction.exists());
    }

    #[test]
    fn recovery_commits_verified_inventory_without_starting_agent() {
        let fixture = Fixture::new(UpdatePhase::Verified, true, true);
        recover_windows_handoff(&fixture.root).unwrap();
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            fixture.new_exe
        );
        assert_eq!(
            fs::read(fixture.root.join(INSTALL_METADATA)).unwrap(),
            fixture.new_metadata
        );
        assert!(!fixture.journal.exists());
        assert!(!fixture.transaction.exists());
    }

    #[test]
    fn recovery_refuses_unknown_child_before_mutating_journal_or_install() {
        let fixture = Fixture::new(UpdatePhase::BackedUp, true, false);
        let exe = fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap();
        write_private_synced(&fixture.transaction.join("unexpected.bin"), b"unknown")
            .expect("extra test artifact");
        assert!(recover_windows_handoff(&fixture.root).is_err());
        assert!(fixture.journal.exists());
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            exe
        );
        assert!(fixture.transaction.join("unexpected.bin").exists());
    }

    #[test]
    fn recovery_refuses_wrong_backup_without_mutation() {
        let fixture = Fixture::new(UpdatePhase::BackedUp, true, false);
        fs::remove_file(fixture.transaction.join("backup-agent.exe")).unwrap();
        write_private_synced(
            &fixture.transaction.join("backup-agent.exe"),
            b"wrong backup",
        )
        .expect("tampered test backup");
        let exe = fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap();
        assert!(recover_windows_handoff(&fixture.root).is_err());
        assert!(fixture.journal.exists());
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            exe
        );
    }

    #[test]
    fn recovery_refuses_hardlinked_backup_before_changing_journal_or_install() {
        let fixture = Fixture::new(UpdatePhase::BackedUp, true, false);
        let alias = fixture.root.join("backup-alias.exe");
        fs::hard_link(fixture.transaction.join("backup-agent.exe"), &alias).unwrap();
        let journal = fs::read(&fixture.journal).unwrap();
        let exe = fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap();
        assert!(recover_windows_handoff(&fixture.root).is_err());
        assert_eq!(fs::read(&fixture.journal).unwrap(), journal);
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            exe
        );
        assert_eq!(fs::read(alias).unwrap(), fixture.old_exe);
    }

    #[test]
    fn private_copy_verifies_source_before_creating_destination() {
        use crate::update::windows::fs::copy_private_synced;
        let fixture = Fixture::new(UpdatePhase::Staged, false, false);
        let source = fixture.transaction.join("backup-agent.exe");
        let destination = fixture.root.join("copy.exe");
        copy_private_synced(&source, &destination).unwrap();
        let dir = private_fs::PrivateDir::open(&fixture.root).unwrap();
        dir.open_file("copy.exe").unwrap().verify().unwrap();
        fs::hard_link(&source, fixture.root.join("alias.exe")).unwrap();
        let refused = fixture.root.join("refused.exe");
        assert!(copy_private_synced(&source, &refused).is_err());
        assert!(!refused.exists());
        assert_eq!(fs::read(&source).unwrap(), fixture.old_exe);
    }

    #[test]
    fn recovery_refuses_tampered_journal_digest_without_mutation() {
        let fixture = Fixture::new(UpdatePhase::BackedUp, true, false);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.journal).unwrap()).unwrap();
        value["transaction_sha256"] = serde_json::Value::String("d".repeat(64));
        fs::write(&fixture.journal, serde_json::to_vec(&value).unwrap()).unwrap();
        let exe = fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap();
        assert!(recover_windows_handoff(&fixture.root).is_err());
        assert!(fixture.journal.exists());
        assert_eq!(
            fs::read(fixture.root.join("bin/hostlink-agent.exe")).unwrap(),
            exe
        );
    }
}
