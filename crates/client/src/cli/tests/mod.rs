use super::*;
use crate::cli::{
    args::{Cli, Command, JobCommand},
    commands::job::{validate_job_id, write_job_status},
};
use clap::Parser;
use hostlink::run::{JobState, JobStatus, sealed_artifact_name};
use sha2::{Digest as _, Sha256};
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
fn run_parses_test_runner_arguments_without_shell_reinterpretation() {
    let cli = Cli::try_parse_from([
        "hostlink",
        "jobs",
        "run",
        "--config",
        "host.json",
        "--binary",
        "runner",
        "--id",
        "01ARZ3NDEKTSV4RRFFQ69G5FA2",
        "--",
        "--list",
        "suite::test name",
        "--exact",
    ])
    .unwrap();
    let Command::Jobs {
        command: JobCommand::Run { args, wait, .. },
    } = cli.command
    else {
        panic!("expected run command");
    };
    assert_eq!(args, ["--list", "suite::test name", "--exact"]);
    assert!(!wait);
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "run",
            "--binary",
            "runner",
            "--config",
            "host.json"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "jobs",
            "run",
            "--program",
            "/bin/sh",
            "--config",
            "host.json"
        ])
        .is_err()
    );
}

#[test]
fn run_local_binary_validation_rejects_directories_and_symlinks() {
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
fn run_staging_name_is_the_digest_bound_seal_name() {
    let bytes = b"runner payload";
    let digest = format!("{:x}", Sha256::digest(bytes));
    let artifact_name = sealed_artifact_name(&digest).unwrap();
    assert_eq!(artifact_name.len(), 71);
    assert_eq!(artifact_name, format!("{digest}.upload"));
}

#[test]
fn job_subcommands_reject_invalid_required_values() {
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "jobs",
            "status",
            "--config",
            "host.json",
            "--id",
            "not-a-uuid",
        ])
        .is_ok()
    );
    assert!(validate_job_id("not-a-uuid").is_err());
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "jobs",
            "logs",
            "--config",
            "host.json",
            "--id",
            "01ARZ3NDEKTSV4RRFFQ69G5FA2",
            "--stream",
            "combined",
            "--offset",
            "0",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "jobs",
            "logs",
            "--config",
            "host.json",
            "--id",
            "01ARZ3NDEKTSV4RRFFQ69G5FA2",
            "--stream",
            "stdout",
        ])
        .is_err()
    );
}

#[test]
fn job_status_output_preserves_exit_code_and_omits_unknown_code() {
    let exited = JobStatus {
        id: "01ARZ3NDEKTSV4RRFFQ69G5FA2".into(),
        state: JobState::Exited { code: 7 },
    };
    let mut bytes = Vec::new();
    write_job_status(&exited, &mut bytes).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"id": exited.id, "state": {"state": "exited", "code": 7}})
    );

    let running = JobStatus {
        id: exited.id,
        state: JobState::Running,
    };
    bytes.clear();
    write_job_status(&running, &mut bytes).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"id": running.id, "state": {"state": "running"}})
    );
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
fn new_output_never_overwrites_existing_data() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("out");
    create_new_output(&path, b"old").unwrap();
    assert!(create_new_output(&path, b"new").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"old");
}

#[test]
fn jobs_list_validates_native_filters_and_page_bounds() {
    let cli = Cli::try_parse_from([
        "hostlink",
        "jobs",
        "list",
        "--config",
        "host.json",
        "--status",
        "Done",
        "--page",
        "2",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Jobs {
            command: JobCommand::List {
                page: 2,
                status: Some(_),
                ..
            }
        }
    ));
    for page in ["0", "129"] {
        assert!(
            Cli::try_parse_from([
                "hostlink",
                "jobs",
                "list",
                "--config",
                "host.json",
                "--page",
                page
            ])
            .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "jobs",
            "list",
            "--config",
            "host.json",
            "--status",
            "unknown"
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["hostlink", "job", "status"]).is_err());
    assert!(Cli::try_parse_from(["hostlink", "jobs", "start"]).is_err());
    assert!(Cli::try_parse_from(["hostlink", "jobs", "output"]).is_err());
}
