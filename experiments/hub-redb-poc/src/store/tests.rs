use super::{HubStore, JsonStore, RedbStore, Snapshot, read_json};
use std::{io, sync::Arc, thread};
use tempfile::tempdir;

fn stores() -> (tempfile::TempDir, JsonStore, tempfile::TempDir, RedbStore) {
    let json_dir = tempdir().expect("json tempdir");
    let redb_dir = tempdir().expect("redb tempdir");
    let json = JsonStore::open(json_dir.path()).expect("open json baseline");
    let redb = RedbStore::open(redb_dir.path().join("hub.redb")).expect("open redb");
    (json_dir, json, redb_dir, redb)
}

fn check_domain_contract(store: &impl HubStore) {
    store
        .register_host("host-1", "alpha", 22001)
        .expect("register host");
    assert!(store.register_host("host-2", "ALPHA", 22002).is_err());
    assert!(store.register_host("host-2", "beta", 22001).is_err());
    store
        .create_invite(&"a".repeat(64), 500)
        .expect("create invite");
    store
        .redeem_invite(&"a".repeat(64), "host-1", 400)
        .expect("redeem once");
    assert!(store.redeem_invite(&"a".repeat(64), "host-1", 400).is_err());
    store
        .create_invite(&"b".repeat(64), 500)
        .expect("create expiring invite");
    assert!(store.redeem_invite(&"b".repeat(64), "host-1", 500).is_err());
}

#[test]
fn both_backends_enforce_host_and_one_use_invite_invariants() {
    let (_jd, json, _rd, redb) = stores();
    check_domain_contract(&json);
    check_domain_contract(&redb);
}

#[test]
fn failed_redemption_rolls_back_partial_state_in_both_backends() {
    let (_jd, json, _rd, redb) = stores();
    for store in [&json as &dyn HubStore, &redb as &dyn HubStore] {
        store
            .register_host("host-1", "alpha", 22001)
            .expect("register host");
        store
            .create_invite(&"c".repeat(64), 500)
            .expect("create invite");
        let before = store.snapshot().expect("before snapshot");
        assert!(
            store
                .redeem_invite(&"c".repeat(64), "missing-host", 1)
                .is_err()
        );
        assert_eq!(store.snapshot().expect("after snapshot"), before);
    }
}

#[test]
fn committed_records_survive_reopen_and_readback() {
    let json_dir = tempdir().expect("json tempdir");
    let redb_dir = tempdir().expect("redb tempdir");
    let json = JsonStore::open(json_dir.path()).expect("open json");
    json.register_host("host-1", "alpha", 22001)
        .expect("write json");
    drop(json);
    let reopened_json = JsonStore::open(json_dir.path()).expect("reopen json");
    assert_eq!(
        reopened_json.snapshot().expect("read json").hosts["host-1"].name,
        "alpha"
    );

    let path = redb_dir.path().join("hub.redb");
    let redb = RedbStore::open(&path).expect("open redb");
    redb.register_host("host-1", "alpha", 22001)
        .expect("write redb");
    drop(redb);
    let reopened_redb = RedbStore::open(&path).expect("reopen redb");
    assert_eq!(
        reopened_redb.snapshot().expect("read redb").hosts["host-1"].name,
        "alpha"
    );
}

#[test]
fn malformed_or_invalid_json_import_fails_closed() {
    let dir = tempdir().expect("tempdir");
    let malformed = dir.path().join("malformed.json");
    std::fs::write(&malformed, b"{not-json").expect("write malformed");
    assert_eq!(
        read_json(&malformed)
            .expect_err("malformed JSON rejected")
            .kind(),
        io::ErrorKind::InvalidData
    );
    let invalid = dir.path().join("invalid.json");
    let mut state = Snapshot::empty();
    state.hosts.insert(
        "one".into(),
        super::Host {
            name: "alpha".into(),
            port: 1,
        },
    );
    state.hosts.insert(
        "two".into(),
        super::Host {
            name: "ALPHA".into(),
            port: 2,
        },
    );
    std::fs::write(
        &invalid,
        serde_json::to_vec(&state).expect("encode invalid"),
    )
    .expect("write invalid");
    assert_eq!(
        read_json(&invalid)
            .expect_err("duplicate identity rejected")
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn concurrent_redb_readers_observe_committed_snapshots_during_writes() {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(RedbStore::open(dir.path().join("hub.redb")).expect("open redb"));
    let reader = Arc::clone(&store);
    let read_thread = thread::spawn(move || {
        for _ in 0..100 {
            reader.snapshot().expect("consistent read");
        }
    });
    for index in 0..50 {
        store
            .register_host(
                &format!("host-{index}"),
                &format!("name-{index}"),
                22000 + index,
            )
            .expect("writer commit");
    }
    read_thread.join().expect("reader thread");
    assert_eq!(store.snapshot().expect("final read").hosts.len(), 50);
}

#[test]
fn redb_rollback_drop_discards_uncommitted_write() {
    let dir = tempdir().expect("tempdir");
    let store = RedbStore::open(dir.path().join("hub.redb")).expect("open redb");
    assert!(
        store
            .rollback_probe()
            .expect("read after rollback")
            .hosts
            .is_empty()
    );
}
