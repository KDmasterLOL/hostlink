#![cfg(windows)]

use hostlink_agent::jobs::JobStore;
use private_fs::PrivateDir;
use std::{fs, path::Path};
use windows_permissions::{
    constants::{AceType, SeObjectType::SE_FILE_OBJECT, SecurityInformation},
    utilities::current_process_sid,
    wrappers::GetSecurityInfo,
};

fn assert_owner_only_acl(path: &Path) {
    let file = fs::File::open(path).expect("read SQLite-created file ACL");
    let descriptor = GetSecurityInfo(
        &file,
        SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .expect("query SQLite file security descriptor");
    let user = current_process_sid().expect("current test user SID");
    assert_eq!(descriptor.owner(), Some(user.as_ref()));
    let dacl = descriptor.dacl().expect("SQLite file DACL must be present");
    assert!(dacl.len() > 0, "SQLite file DACL must not be empty");
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).expect("valid SQLite ACL entry");
        assert_eq!(ace.ace_type(), AceType::ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(ace.sid(), Some(user.as_ref()), "foreign SQLite ACE");
    }
}

#[tokio::test]
async fn sqlite_files_inherit_only_the_agent_user() {
    let temp = tempfile::tempdir().expect("disposable local test directory");
    let root = temp.path().join("private");
    let private = PrivateDir::ensure(&root).expect("owner-only private root");
    private
        .create_dir("jobs")
        .expect("owner-only inheritable jobs root");
    let jobs = root.join("jobs");

    let store = JobStore::initialize_fresh(&jobs)
        .await
        .expect("create Apalis SQLite database");
    let mut saw_database = false;
    for entry in fs::read_dir(&jobs).expect("list SQLite files") {
        let entry = entry.expect("SQLite file entry");
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("jobs.db") {
            saw_database |= name == "jobs.db";
            assert_owner_only_acl(&entry.path());
        }
    }
    assert!(saw_database, "SQLite database must have been created");

    // Exercise Windows default file security independently of SQLite's open
    // sidecars, which it may delete automatically on the last connection.
    fs::write(jobs.join("default-dacl-probe"), b"private")
        .expect("CreateFileW without a custom security descriptor");
    assert_owner_only_acl(&jobs.join("default-dacl-probe"));
    store.close().await;
}
