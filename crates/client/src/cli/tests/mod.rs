use super::*;
use crate::cli::{
    args::{Cli, Command, JobCommand},
    commands::{
        job::{validate_job_id, validate_job_spec, write_job_status},
        run::{PreparedRun, sftp_failure_may_be_existing_file},
    },
};
use clap::Parser;
use hostlink::{
    connect::SshClientError,
    run::{JobSpec, JobState, JobStatus, sealed_artifact_name},
};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File};

#[test]
fn job_start_parses_exact_argument_vector_after_separator() {
    let cli = Cli::try_parse_from([
        "hostlink",
        "job",
        "start",
        "--config",
        "host.json",
        "--program",
        "/opt/tests/bin",
        "--source-sha256",
        &"a".repeat(64),
        "--",
        "--list",
        "suite::test name",
    ])
    .unwrap();
    let Command::Job {
        command:
            JobCommand::Start {
                program,
                source_sha256,
                args,
                ..
            },
    } = cli.command
    else {
        panic!("expected job start command");
    };
    assert_eq!(program, "/opt/tests/bin");
    assert_eq!(source_sha256, "a".repeat(64));
    assert_eq!(args, ["--list", "suite::test name"]);
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
fn run_parses_test_runner_arguments_without_shell_reinterpretation() {
    let cli = Cli::try_parse_from([
        "hostlink",
        "run",
        "--config",
        "host.json",
        "--binary",
        "runner",
        "--id",
        "00000000-0000-4000-8000-000000000000",
        "--",
        "--list",
        "suite::test name",
        "--exact",
    ])
    .unwrap();
    let Command::Run { args, .. } = cli.command else {
        panic!("expected run command");
    };
    assert_eq!(args, ["--list", "suite::test name", "--exact"]);
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
    let prepared = PreparedRun {
        id: "00000000-0000-4000-8000-000000000000".into(),
        bytes: bytes.to_vec(),
        digest: digest.clone(),
        artifact_name: artifact_name.clone(),
        args: vec!["--list".into()],
    };
    assert_eq!(
        prepared.artifact_name,
        format!("{}.upload", prepared.digest)
    );
    let seal = prepared.seal_request();
    assert_eq!(seal.name, prepared.artifact_name);
    assert_eq!(seal.sha256, prepared.digest);
    assert_eq!(seal.size, bytes.len() as u64);
    assert_eq!(prepared.bytes, bytes);
}

#[test]
fn only_generic_remote_sftp_failure_can_enter_exact_seal_verification() {
    let failure = || {
        SshClientError::Sftp(russh_sftp::client::error::Error::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: russh_sftp::protocol::StatusCode::Failure,
                error_message: "Failure".into(),
                language_tag: "en-US".into(),
            },
        ))
    };
    let denied = SshClientError::Sftp(russh_sftp::client::error::Error::Status(
        russh_sftp::protocol::Status {
            id: 1,
            status_code: russh_sftp::protocol::StatusCode::PermissionDenied,
            error_message: "Permission denied".into(),
            language_tag: "en-US".into(),
        },
    ));
    assert!(sftp_failure_may_be_existing_file(&failure()));
    assert!(!sftp_failure_may_be_existing_file(&denied));
    assert!(!sftp_failure_may_be_existing_file(&SshClientError::Timeout));
}

#[test]
fn job_subcommands_reject_invalid_required_values() {
    assert!(
        Cli::try_parse_from([
            "hostlink",
            "job",
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
            "job",
            "output",
            "--config",
            "host.json",
            "--id",
            "00000000-0000-4000-8000-000000000000",
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
            "job",
            "output",
            "--config",
            "host.json",
            "--id",
            "00000000-0000-4000-8000-000000000000",
            "--stream",
            "stdout",
        ])
        .is_err()
    );
}

#[test]
fn job_start_validation_rejects_non_absolute_program_and_bad_digest() {
    let mut spec = JobSpec {
        program: "relative/program".into(),
        args: Vec::new(),
        cwd: None,
        source_sha256: "a".repeat(64),
    };
    assert!(validate_job_spec(&spec).is_err());
    spec.program = "/absolute/program".into();
    spec.source_sha256 = "A".repeat(64);
    assert!(validate_job_spec(&spec).is_err());
}

#[test]
fn job_status_output_preserves_exit_code_and_omits_unknown_code() {
    let exited = JobStatus {
        id: "00000000-0000-4000-8000-000000000000".into(),
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
