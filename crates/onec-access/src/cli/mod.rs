//! Human-facing controller CLI for managed-machine access.

use hostlink_access::*;
use hostlink_protocol::{AgentJobInfo, AgentJobState, AgentResponseKind};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

mod bootstrap;
mod commands;
mod config;
mod display_name;
mod execution_evidence;
mod input;
mod inventory;
mod jobs;
mod mutable_lease;
mod native_attestation;
mod native_invocation_observation;
mod output;
mod run_local_job;
mod secrets;
mod ssh;
mod transport;
pub(crate) mod values;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "hostlink",
    version,
    about = "HostLink managed-machine controller"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: commands::AccessCommand,
}

pub(crate) async fn run(command: commands::AccessCommand) -> AppResult<Option<i32>> {
    commands::run(command).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};
    use commands::{AccessCommand, job::Command as JobCommand};

    #[test]
    fn surface_is_machine_only() {
        for argv in [
            vec!["hostlink", "list", "--json"],
            vec!["hostlink", "display-name", "host-a", "Тестовый сервер"],
            vec!["hostlink", "display-name", "host-a", "--clear"],
            vec!["hostlink", "verify", "host-a", "--json"],
            vec!["hostlink", "exec", "host-a", "--", "hostname"],
            vec![
                "hostlink",
                "run-local",
                "--target",
                "host-a",
                "--required-effect",
                "run-owned",
                "--map-file-env",
                "NEXTEST_BIN_EXE_onec",
                "--",
                "./native-readonly.exe",
                "--list",
            ],
            vec![
                "hostlink",
                "exec",
                "host-a",
                "--secret-env",
                "REMOTE_PASSWORD=ONEC_TEST_ADMIN_PASSWORD",
                "--stdin-file",
                "-",
                "--",
                "hostname",
            ],
            vec![
                "hostlink",
                "job",
                "start",
                "host-a",
                "--secret-env",
                "REMOTE_PASSWORD=ONEC_TEST_ADMIN_PASSWORD",
                "--stdin-file",
                "input.txt",
                "--",
                "hostname",
            ],
            vec!["hostlink", "job", "status", "host-a", "job-1"],
            vec![
                "hostlink",
                "remove-scoped",
                "host-a",
                r"C:\Temp\onec-toolkit",
                r"C:\Temp\onec-toolkit\run-1",
                "--recursive",
                "--missing-ok",
                "--json",
            ],
            vec!["hostlink", "sync-ssh", "--json"],
            vec!["hostlink", "ssh", "host-a"],
        ] {
            Cli::try_parse_from(argv).expect("machine-access command must parse");
        }

        for forbidden in ["1c", "project", "update", "storage", "distribution"] {
            let error = Cli::try_parse_from(["hostlink", forbidden])
                .expect_err("domain command must not exist in access product");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
        }
    }

    #[test]
    fn display_name_requires_explicit_set_or_clear() {
        let no_label = Cli::try_parse_from(["hostlink", "display-name", "server-a"])
            .expect_err("label must be supplied or cleared");
        assert_eq!(no_label.kind(), ErrorKind::MissingRequiredArgument);
        Cli::try_parse_from(["hostlink", "display-name", "server-a", "--clear"])
            .expect("explicit clear");
        Cli::try_parse_from(["hostlink", "display-name", "server-a", "Тестовый сервер"])
            .expect("UTF-8 display label");
        assert!(
            Cli::try_parse_from(["hostlink", "display-name", "server-a", "--clear", "label"])
                .is_err()
        );
    }

    #[test]
    fn command_help_keeps_the_full_nested_leaf_catalog() {
        let mut command = Cli::command();
        command.clone().debug_assert();
        let root_help = command.render_long_help().to_string();
        assert!(root_help.contains("Usage: hostlink"));
        for top_level in ["job", "run-local-job", "run-local-evidence"] {
            assert!(
                root_help.contains(top_level),
                "root help includes {top_level}"
            );
        }

        let expected: [(&str, &[&str]); 3] = [
            (
                "job",
                &["start", "status", "result", "logs", "cancel", "wait"],
            ),
            (
                "run-local-job",
                &[
                    "start",
                    "status",
                    "logs",
                    "cancel",
                    "results",
                    "attest",
                    "recover-attest",
                    "observe-invocation",
                    "recover-invocation",
                    "verify-invocation-logs",
                    "verify-invocation-result",
                    "cleanup",
                    "list-reservations",
                ],
            ),
            ("run-local-evidence", &["verify"]),
        ];
        for (family_name, leaves) in expected {
            let family = command
                .find_subcommand_mut(family_name)
                .unwrap_or_else(|| panic!("missing {family_name} help"));
            let actual = family
                .get_subcommands()
                .map(|leaf| leaf.get_name())
                .collect::<Vec<_>>();
            assert_eq!(actual, leaves, "{family_name} leaf help names");
            let help = family.render_long_help().to_string();
            for leaf in leaves {
                assert!(help.contains(leaf), "{family_name} help includes {leaf}");
            }
        }
    }

    #[test]
    fn run_local_job_lifecycle_commands_parse_with_run_identity() {
        let cli = Cli::try_parse_from([
            "hostlink",
            "run-local-job",
            "start",
            "--target",
            "host-a",
            "--required-effect",
            "run-owned",
            "--map-file-env",
            "INPUT_FILE",
            "--",
            "./candidate.exe",
            "--suite",
            "bounded",
        ])
        .expect("durable run-local start parses");
        let AccessCommand::RunLocalJob(args) = cli.command else {
            panic!("expected durable run-local start");
        };
        let commands::run_local_job::Command::Start(args) = args.command else {
            panic!("expected durable run-local start leaf");
        };
        assert_eq!(args.command, ["./candidate.exe", "--suite", "bounded"]);

        let cli = Cli::try_parse_from([
            "hostlink",
            "run-local-job",
            "start",
            "--target",
            "host-a",
            "--required-effect",
            "run-owned",
            "--require-cached-candidate",
            "--",
            "./candidate.exe",
        ])
        .expect("cache-only durable run-local start parses");
        assert!(matches!(
            cli.command,
            AccessCommand::RunLocalJob(args)
                if matches!(args.command, commands::run_local_job::Command::Start(ref start)
                    if start.require_cached_candidate)
        ));
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "run-local-job",
                "status",
                "host-a",
                "0123456789abcdef0123456789abcdef",
                "--require-cached-candidate",
            ])
            .is_err(),
            "cache-only selection belongs only to durable run-local start"
        );
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("run-local-job")
            .expect("run-local-job help")
            .find_subcommand_mut("start")
            .expect("run-local-job start help")
            .render_long_help()
            .to_string();
        assert!(help.contains("already exist in the Agent cache; never upload it"));

        let cli = Cli::try_parse_from([
            "hostlink",
            "run-local-job",
            "start",
            "--target",
            "host-a",
            "--required-effect",
            "run-owned",
            "--native-effect",
            "disposable",
            "--native-suite-policy",
            "suite-policy.json",
            "--",
            "./candidate.exe",
            "--suite",
            "bounded",
        ])
        .expect("explicit native invocation mode parses");
        let AccessCommand::RunLocalJob(args) = cli.command else {
            panic!("expected explicit native invocation effect");
        };
        let commands::run_local_job::Command::Start(args) = args.command else {
            panic!("expected explicit native invocation effect");
        };
        assert_eq!(
            args.native_effect,
            Some(values::NativeExecutionEffect::Disposable)
        );
        assert_eq!(
            args.native_suite_policy.as_deref(),
            Some(std::path::Path::new("suite-policy.json"))
        );
        assert_eq!(args.command, ["./candidate.exe", "--suite", "bounded"]);

        assert!(
            Cli::try_parse_from([
                "hostlink",
                "run-local-job",
                "start",
                "--target",
                "host-a",
                "--required-effect",
                "run-owned",
                "--native-effect",
                "read-only",
                "--",
                "./candidate.exe",
            ])
            .is_err(),
            "durable native invocation does not expose read-only authorization"
        );

        for argv in [
            vec![
                "hostlink",
                "run-local-job",
                "status",
                "host-a",
                "0123456789abcdef0123456789abcdef",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "cleanup",
                "host-a",
                "0123456789abcdef0123456789abcdef",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "observe-invocation",
                "host-a",
                "0123456789abcdef0123456789abcdef",
                "--challenge",
                "challenge-a",
                "--trusted-public-key",
                "trusted-key.hex",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "recover-invocation",
                "host-a",
                "0123456789abcdef0123456789abcdef",
                "--challenge",
                "challenge-a",
                "--trusted-public-key",
                "trusted-key.hex",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "verify-invocation-logs",
                "0123456789abcdef0123456789abcdef",
                "--machine-id",
                "machine-id-a",
                "--challenge",
                "challenge-a",
                "--trusted-public-key",
                "trusted-key.hex",
                "--stdout-log",
                "stdout.log",
                "--stderr-log",
                "stderr.log",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "attest",
                "host-a",
                "0123456789abcdef0123456789abcdef",
                "--challenge",
                "fresh-challenge",
                "--trusted-public-key",
                "agent-public-key.hex",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "recover-attest",
                "host-a",
                "0123456789abcdef0123456789abcdef",
                "--challenge",
                "fresh-challenge",
                "--trusted-public-key",
                "agent-public-key.hex",
            ],
            vec![
                "hostlink",
                "run-local-job",
                "list-reservations",
                "host-a",
                "--json",
            ],
        ] {
            Cli::try_parse_from(argv).expect("each run-local-job leaf parses");
        }
    }

    #[test]
    fn run_local_preserves_cargo_runner_argv_and_generic_file_mapping() {
        let parsed = Cli::try_parse_from([
            "hostlink",
            "run-local",
            "--target",
            "windows-test",
            "--required-effect",
            "run-owned",
            "--map-file-env",
            "NEXTEST_BIN_EXE_onec",
            "--env",
            "RUST_BACKTRACE=1",
            "--",
            "./native_readonly.exe",
            "--list",
            "--format",
            "terse",
            "module::test_name",
            "--nocapture",
        ])
        .expect("run-local must parse Cargo/Nextest argv without interpreting it");

        let AccessCommand::RunLocal(args) = parsed.command else {
            panic!("expected run-local command");
        };
        assert_eq!(args.target.as_deref(), Some("windows-test"));
        assert_eq!(args.required_effect, values::TargetEffect::RunOwned);
        assert_eq!(args.env, ["RUST_BACKTRACE=1"]);
        assert_eq!(args.map_file_env, ["NEXTEST_BIN_EXE_onec"]);
        assert_eq!(
            args.timeout_ms,
            hostlink_protocol::MAX_EXEC_TIMEOUT_MS,
            "run-local must leave the earlier per-test timeout to Nextest and keep only the protocol safety ceiling"
        );
        assert_eq!(
            args.command,
            [
                "./native_readonly.exe",
                "--list",
                "--format",
                "terse",
                "module::test_name",
                "--nocapture"
            ]
        );
    }

    #[test]
    fn ordinary_exec_keeps_the_shorter_operator_timeout_default() {
        let parsed =
            Cli::try_parse_from(["hostlink", "exec", "host-a", "--", "hostname"]).expect("exec");
        let AccessCommand::Exec(args) = parsed.command else {
            panic!("expected exec command");
        };
        assert_eq!(args.timeout_ms, hostlink_protocol::DEFAULT_EXEC_TIMEOUT_MS);
    }

    #[test]
    fn run_local_defaults_to_the_protocol_emergency_ceiling() {
        let parsed = Cli::try_parse_from([
            "hostlink",
            "run-local",
            "--required-effect",
            "disposable",
            "--",
            "./candidate.exe",
        ])
        .expect("run-local");
        let AccessCommand::RunLocal(args) = parsed.command else {
            panic!("expected run-local command");
        };
        assert_eq!(args.timeout_ms, hostlink_protocol::MAX_EXEC_TIMEOUT_MS);
        assert!(args.timeout_ms > 9 * 60 * 1000);
    }

    #[test]
    fn run_local_requires_explicit_effect_classification() {
        let error = Cli::try_parse_from(["hostlink", "run-local", "--", "./candidate.exe"])
            .expect_err("run-local must not infer an effect");
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);

        for effect in ["read-only", "run-owned", "disposable"] {
            Cli::try_parse_from([
                "hostlink",
                "run-local",
                "--required-effect",
                effect,
                "--",
                "./candidate.exe",
            ])
            .unwrap_or_else(|error| panic!("explicit effect {effect} must parse: {error}"));
        }
    }

    #[test]
    fn run_local_rejects_discovery_bypass_option_and_accepts_arbitrary_executable() {
        let parsed = Cli::try_parse_from([
            "hostlink",
            "run-local",
            "--required-effect",
            "disposable",
            "--",
            "./arbitrary.exe",
            "--list",
            "--format",
            "terse",
        ])
        .expect("run-local accepts executable arguments without a lease bypass option");
        let AccessCommand::RunLocal(args) = parsed.command else {
            panic!("expected run-local command");
        };
        assert_eq!(
            args.command,
            ["./arbitrary.exe", "--list", "--format", "terse"]
        );

        let error = Cli::try_parse_from([
            "hostlink",
            "run-local",
            "--required-effect",
            "disposable",
            "--allow-libtest-discovery-concurrency",
            "--",
            "./native_disposable.exe",
            "--list",
            "--format",
            "terse",
        ])
        .expect_err("untrusted discovery bypass option must be removed from public grammar");
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn exec_composes_secret_stdin_and_result_options() {
        let parsed = Cli::try_parse_from([
            "hostlink",
            "exec",
            "host-a",
            "--secret-env",
            "ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD",
            "--stdin-file",
            "request.json",
            "--result",
            "report.json=1048576",
            "--result-dir",
            "./results",
            "--",
            "onec",
            "diagnose",
        ])
        .expect("combined typed immediate-exec options must parse");
        let AccessCommand::Exec(args) = parsed.command else {
            panic!("expected exec command");
        };
        assert_eq!(args.name, "host-a");
        assert_eq!(
            args.secret_env,
            ["ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD"]
        );
        assert_eq!(
            args.stdin_file.as_deref(),
            Some(std::path::Path::new("request.json"))
        );
        assert_eq!(args.results, ["report.json=1048576"]);
        assert_eq!(
            args.result_dir.as_deref(),
            Some(std::path::Path::new("./results"))
        );
        assert_eq!(args.command, ["onec", "diagnose"]);
    }

    #[test]
    fn job_start_composes_secret_stdin_and_result_options() {
        let parsed = Cli::try_parse_from([
            "hostlink",
            "job",
            "start",
            "host-a",
            "--secret-env",
            "ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD",
            "--stdin-file",
            "request.json",
            "--result",
            "report.json=1048576",
            "--",
            "onec",
            "diagnose",
        ])
        .expect("combined typed durable-job options must parse");
        let AccessCommand::Job(args) = parsed.command else {
            panic!("expected job command");
        };
        let JobCommand::Start(args) = args.command else {
            panic!("expected job start command");
        };
        assert_eq!(args.name, "host-a");
        assert_eq!(
            args.secret_env,
            ["ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD"]
        );
        assert_eq!(
            args.stdin_file.as_deref(),
            Some(std::path::Path::new("request.json"))
        );
        assert_eq!(args.results, ["report.json=1048576"]);
        assert_eq!(args.command, ["onec", "diagnose"]);
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "job",
                "start",
                "host-a",
                "--result-dir",
                "./results",
                "--",
                "onec",
                "diagnose",
            ])
            .is_err(),
            "durable job start must leave result publication directory to later job-result retrieval"
        );
    }

    #[test]
    fn secret_environment_accepts_local_env_references_only() {
        for forbidden_flag in ["--secret", "--secret-env-alias"] {
            let error = Cli::try_parse_from([
                "hostlink",
                "exec",
                "host-a",
                forbidden_flag,
                "REMOTE_PASSWORD=ONEC_LOCAL_SECRET_SOURCE",
                "--",
                "hostname",
            ])
            .expect_err("plaintext secret CLI form must not exist");
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }

        Cli::try_parse_from([
            "hostlink",
            "exec",
            "host-a",
            "--secret-env",
            "REMOTE_PASSWORD=ONEC_PRODUCTION_PASSWORD",
            "--",
            "hostname",
        ])
        .expect("reference-only local environment form must parse");
    }

    #[test]
    fn removed_target_effect_command_is_rejected() {
        let error = Cli::try_parse_from(["hostlink", "target-effect", "show", "host-a"])
            .expect_err("retired per-target effect commands are unsupported");
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn invite_requires_complete_direct_pins_and_rejects_retired_release_flags() {
        let missing = Cli::try_parse_from(["hostlink", "invite"])
            .expect_err("invite requires all direct artifact pins");
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        let retired = Cli::try_parse_from([
            "hostlink",
            "invite",
            "--release-id",
            "old",
            "--release-manifest-sha256",
            "old",
        ])
        .expect_err("retired release flags must be rejected");
        assert_eq!(retired.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn invite_embedded_ssh_candidate_remains_an_explicit_opt_in() {
        Cli::try_parse_from([
            "hostlink",
            "invite",
            "--embedded-ssh-candidate",
            "--direct-installer-url",
            "https://downloads.example.test/Install-OnecToolkit.ps1",
            "--direct-installer-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--direct-package-url",
            "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            "--direct-package-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--direct-package-version",
            "1.2.3",
            "--direct-package-target",
            "x86_64-win7-windows-msvc",
        ])
        .expect("embedded SSH candidate flag and complete direct pin must parse");
    }

    #[test]
    fn migrate_runtime_help_requires_direct_artifact_pins() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("migrate-runtime"));
        let migration = command
            .find_subcommand_mut("migrate-runtime")
            .expect("migration command help");
        let help = migration.render_long_help().to_string();
        assert!(help.contains("--direct-installer-url"));
        assert!(help.contains("--direct-package-sha256"));
        assert!(help.contains("--direct-package-version"));
        assert!(help.contains("--direct-package-target"));
        assert!(help.contains("--persistence"));
    }

    #[test]
    fn migration_report_supports_human_and_json_modes() {
        Cli::try_parse_from(["hostlink", "migration-report"])
            .expect("human-readable migration report must parse");
        Cli::try_parse_from(["hostlink", "migration-report", "--json"])
            .expect("JSON migration report must parse");
    }
}
