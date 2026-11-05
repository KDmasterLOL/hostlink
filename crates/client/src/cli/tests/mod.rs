use super::*;
use crate::cli::args::{Cli, Command};
use crate::cli::invite::Target;
use clap::Parser;
use std::fs::{self, File};

#[test]
fn release_invite_requires_name_target_and_preserves_token_only() {
    let base = [
        "hostlink",
        "invite",
        "--name",
        "fixture",
        "--target",
        "x86_64-unknown-linux-gnu",
    ];
    assert!(Cli::try_parse_from(base).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--version", "1.2.3"])).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--embed-github-token"])).is_err());
    assert!(Cli::try_parse_from(["hostlink", "invite", "--token-only"]).is_ok());
    assert!(Cli::try_parse_from(["hostlink", "invite"]).is_err());
    for flags in [
        vec!["--target", "x86_64-unknown-linux-gnu"],
        vec!["--ssh-user", "agent"],
        vec!["--version", "1.2.3"],
        vec!["--bootstrap-hub-ca-cert", "ca.pem"],
        vec!["--gateway-index", "0"],
    ] {
        let error = Cli::try_parse_from(
            ["hostlink", "invite", "--token-only"]
                .into_iter()
                .chain(flags),
        )
        .err()
        .expect("token-only must conflict with bootstrap options");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    assert!(Cli::try_parse_from(base.into_iter().chain(["--token-only"])).is_err());
    for flag in [
        "--installer-url",
        "--installer-sha256",
        "--agent-url",
        "--agent-sha256",
        "--archive-url",
        "--archive-sha256",
        "--github-token",
    ] {
        assert!(Cli::try_parse_from(base.into_iter().chain([flag, "fixture"])).is_err());
    }
}

#[test]
fn invite_family_and_legacy_flags_are_exclusive() {
    for os in ["windows", "linux"] {
        assert!(Cli::try_parse_from(["hostlink", "invite", "fixture", "--os", os]).is_ok());
        assert!(
            Cli::try_parse_from(["hostlink", "invite", "--name", "fixture", "--os", os]).is_ok()
        );
    }
    for args in [
        vec!["fixture", "--os", "macos"],
        vec![
            "fixture",
            "--os",
            "linux",
            "--target",
            "x86_64-unknown-linux-gnu",
        ],
        vec!["fixture", "--name", "other", "--os", "linux"],
        vec!["--token-only", "--os", "linux"],
    ] {
        assert!(Cli::try_parse_from(["hostlink", "invite"].into_iter().chain(args)).is_err());
    }
}

#[test]
fn invitation_target_is_parsed_into_the_existing_bootstrap_type() {
    for target in [
        Target::Win7X86,
        Target::Win7X64,
        Target::Win11X64,
        Target::LinuxX64,
    ] {
        let cli = Cli::try_parse_from([
            "hostlink",
            "invite",
            "--name",
            "fixture",
            "--target",
            target.as_str(),
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Invite(crate::cli::args::InviteArgs { target: Some(parsed), .. }) if parsed == target)
        );
    }
    let error = Cli::try_parse_from([
        "hostlink",
        "invite",
        "--name",
        "fixture",
        "--target",
        "unsupported-target",
    ])
    .err()
    .expect("unsupported target must fail during parsing");
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(error.to_string().contains("unsupported bootstrap target"));
}

#[test]
fn detached_timeout_is_bounded_optional_and_requires_detach() {
    let base = [
        "hostlink",
        "exec",
        "--host",
        "fixture",
        "--board-port",
        "39123",
        "--detach",
        "--command",
        "long-running-command",
    ];
    let legacy = Cli::try_parse_from(base).unwrap();
    assert!(matches!(
        legacy.command,
        Command::Exec {
            timeout_seconds: None,
            ..
        }
    ));

    for value in ["1", "900", "14400"] {
        let parsed =
            Cli::try_parse_from(base.into_iter().chain(["--timeout-seconds", value])).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Exec {
                timeout_seconds: Some(_),
                ..
            }
        ));
    }
    for value in ["0", "14401", "-1", "nonsense"] {
        assert!(Cli::try_parse_from(base.into_iter().chain(["--timeout-seconds", value])).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "exec",
            "--host",
            "fixture",
            "--command",
            "echo ok",
            "--timeout-seconds",
            "900",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "exec",
            "--host",
            "fixture",
            "--command",
            "echo ok",
        ])
        .is_ok()
    );
}

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

#[test]
fn invite_gateway_index_is_explicit_and_typed() {
    let args = [
        "hostlink",
        "invite",
        "--name",
        "fixture",
        "--target",
        "x86_64-unknown-linux-gnu",
    ];
    for (extra, expected) in [
        (vec![], None),
        (vec!["--gateway-index", "0"], Some(0)),
        (vec!["--gateway-index", "2"], Some(2)),
    ] {
        let cli = Cli::try_parse_from(args.into_iter().chain(extra)).unwrap();
        assert!(matches!(cli.command, Command::Invite(parsed) if parsed.gateway_index == expected));
    }
    for value in ["-1", "invalid", "1.5", "184467440737095516160"] {
        assert!(Cli::try_parse_from(args.into_iter().chain(["--gateway-index", value])).is_err());
    }
}
