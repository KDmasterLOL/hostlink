use super::*;
use crate::cli::args::{Cli, Command};
use clap::Parser;
use std::fs::{self, File};

#[test]
fn migration_preflight_requires_all_local_explicit_inputs() {
    let cli = Cli::try_parse_from([
        "hostlink",
        "migration",
        "preflight",
        "--old-hub",
        "hub.json",
        "--old-controller",
        "controller.json",
        "--old-agent",
        "agent.json",
        "--new-agent",
        "new-agent.json",
        "--new-host",
        "host.json",
    ])
    .unwrap();
    assert!(matches!(cli.command, Command::Migration { .. }));
}

#[test]
fn local_file_validation_rejects_directories_and_symlinks() {
    let root = tempfile::tempdir().unwrap();
    assert!(read_existing_file(root.path(), MAX_FILE_BYTES).is_err());
    let binary = root.path().join("runner");
    fs::write(&binary, b"test binary").unwrap();
    assert_eq!(
        read_existing_file(&binary, MAX_FILE_BYTES).unwrap(),
        b"test binary"
    );
    let oversized = root.path().join("oversized-runner");
    File::create(&oversized)
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    assert!(read_existing_file(&oversized, MAX_FILE_BYTES).is_err());
    #[cfg(unix)]
    {
        let link = root.path().join("runner-link");
        std::os::unix::fs::symlink(&binary, &link).unwrap();
        assert!(read_existing_file(&link, MAX_FILE_BYTES).is_err());
    }
}

#[test]
fn host_config_rejects_unknown_fields_and_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("host.json");
    fs::write(&path, br#"{"endpoint":"127.0.0.1:27322","user":"hostlink","identity":"key","host_public_key":"pin","gateway":null,"unknown":true}"#).unwrap();
    assert!(load_host_spec(&path).is_err());
    #[cfg(unix)]
    {
        let symlink = root.path().join("link.json");
        std::os::unix::fs::symlink(path, &symlink).unwrap();
        assert!(load_host_spec(&symlink).is_err());
    }
}

#[test]
fn host_config_resolves_relative_alternate_identity_paths() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("host.json");
    fs::write(
        &config,
        r#"{
        "endpoint":"127.0.0.1:2222", "user":"agent",
        "identity":"agent.key", "host_public_key":"pin",
        "gateway":{
            "address":"127.0.0.1:2200", "user":"gateway",
            "identity":"gateway.key", "host_public_key":"gateway-pin",
            "reverse_port":23000,
            "alternates":[{"address":"127.0.0.1:2201", "user":"fallback",
                "identity":"alternate.key", "host_public_key":"fallback-pin"}]
        }
    }"#,
    )
    .unwrap();
    let host = load_host_spec(&config).unwrap();
    assert_eq!(host.identity, root.path().join("agent.key"));
    let gateway = host.gateway.unwrap();
    assert_eq!(gateway.identity, root.path().join("gateway.key"));
    assert_eq!(
        gateway.alternates[0].identity,
        root.path().join("alternate.key")
    );
}

#[test]
fn new_output_never_overwrites_existing_data() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("out");
    create_new_output(&path, b"old").unwrap();
    assert!(create_new_output(&path, b"new").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"old");
}
