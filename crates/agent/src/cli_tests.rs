use super::*;

#[test]
fn all_cli_commands_retain_their_arguments() {
    let valid = [
        vec!["check", "--config", "agent.json"],
        vec!["run", "--config", "agent.json"],
        vec!["update", "--version", "1.0.0"],
        vec![
            "enroll",
            "--hub-url",
            "https://hub.test",
            "--token-file",
            "token",
            "--root",
            "agent",
            "--name",
            "host",
            "--user",
            "agent",
            "--gateway-index",
            "1",
            "--retain-pending",
        ],
        vec![
            "install",
            "--hub-url",
            "https://hub.test",
            "--token-file",
            "token",
            "--name",
            "host",
            "--user",
            "agent",
        ],
        vec!["binary-info"],
        vec![
            "service",
            "install",
            "--root",
            "agent",
            "--config",
            "agent.json",
        ],
        vec!["service", "start", "--root", "agent"],
        vec!["service", "stop", "--root", "agent"],
        vec!["service", "status", "--root", "agent"],
        vec!["service", "remove", "--root", "agent"],
    ];
    for args in valid {
        assert!(
            Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args.iter().copied()))
                .is_ok(),
            "CLI rejected {args:?}"
        );
    }
}

#[test]
fn github_update_accepts_latest_or_exact_version_without_a_root() {
    for args in [vec!["update"], vec!["update", "--version", "1.2.3"]] {
        let parsed = Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args))
            .expect("GitHub release selection must parse without resolving an install root");
        assert!(matches!(parsed.command, Command::Update(_)));
    }
}

#[test]
fn install_has_no_alternate_root_and_archive_bootstrap_commands_are_removed() {
    let args = [
        "hostlink-agent",
        "install",
        "--hub-url",
        "https://hub.test",
        "--token-file",
        "fixture",
        "--name",
        "host",
        "--user",
        "agent",
    ];
    assert!(Cli::try_parse_from(args).is_ok());
    assert!(Cli::try_parse_from(args.into_iter().chain(["--hub-ca-cert", "ca.pem"])).is_ok());
    for flag in ["--root", "--target", "--sha256", "--archive"] {
        assert!(Cli::try_parse_from(args.into_iter().chain([flag, "fixture"])).is_err());
    }
    for command in ["bootstrap-verify", "bootstrap-finalize"] {
        assert!(Cli::try_parse_from(["hostlink-agent", command]).is_err());
    }
}

#[test]
fn update_rejects_manual_source_and_token_arguments() {
    for (flag, value) in [
        ("--url", "https://artifacts.example/agent.zip"),
        ("--sha256", "a5"),
        ("--target", "x86_64-unknown-linux-gnu"),
        ("--token", "fixture-only"),
        ("--token-file", "fixture-only"),
    ] {
        assert!(Cli::try_parse_from(["hostlink-agent", "update", flag, value]).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "hostlink-agent",
            "update",
            "--url",
            "https://artifacts.example/agent.zip",
            "--sha256",
            "a5",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--version",
            "1.2.3",
        ])
        .is_err()
    );
}

#[test]
fn update_rejects_malformed_typed_values() {
    for invalid in ["v1.2.3", "1.2", "latest", ""] {
        assert!(Cli::try_parse_from(["hostlink-agent", "update", "--version", invalid]).is_err());
    }
}

#[test]
fn removed_windows_lifecycle_flags_are_rejected() {
    for flag in ["--managed-service", "--maintenance-start"] {
        assert!(
            Cli::try_parse_from(["hostlink-agent", "run", "--config", "agent.json", flag]).is_err()
        );
    }
}

#[test]
fn top_level_and_service_require_subcommands() {
    for args in [vec![], vec!["service"]] {
        assert!(
            Cli::try_parse_from(std::iter::once("hostlink-agent").chain(args.iter().copied()))
                .is_err()
        );
    }
}

#[test]
fn install_gateway_index_is_explicit_and_typed() {
    let args = [
        "hostlink-agent",
        "install",
        "--hub-url",
        "https://hub.test",
        "--token-file",
        "token",
        "--name",
        "host",
        "--user",
        "agent",
    ];
    for (extra, expected) in [
        (vec![], None),
        (vec!["--gateway-index", "0"], Some(0)),
        (vec!["--gateway-index", "2"], Some(2)),
    ] {
        let cli = Cli::try_parse_from(args.into_iter().chain(extra)).unwrap();
        assert!(
            matches!(cli.command, Command::Install(parsed) if parsed.gateway_index == expected)
        );
    }
    for value in ["-1", "invalid", "1.5", "184467440737095516160"] {
        assert!(Cli::try_parse_from(args.into_iter().chain(["--gateway-index", value])).is_err());
    }
}
