use super::*;
use sha2::Digest as _;

#[test]
fn durable_job_reports_primary_and_scoped_cleanup_failures_and_retains_workspace() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_dir = root.path().join("job-cleanup-failure");
    fs::create_dir(&job_dir).expect("job directory");
    let mut workspace = Some(
        crate::results::ResultWorkspace::prepare_job(
            &job_dir,
            "job-cleanup-failure",
            &[
                onec_agent_protocol::ResultArtifactSpec::try_new("report.bin".to_owned(), 64, None)
                    .expect("valid result declaration"),
            ],
        )
        .expect("prepare")
        .expect("workspace"),
    );
    let incoming = workspace
        .as_ref()
        .expect("workspace")
        .incoming_path()
        .to_path_buf();
    fs::write(incoming.join("report.bin"), b"retained evidence").expect("write evidence");

    let message = workflow::discard_result_workspace_with_primary_and(
        &mut workspace,
        "primary process failure".to_owned(),
        |_workspace| Err(io::Error::other("injected scoped cleanup failure")),
    );

    assert_eq!(
        message,
        "primary process failure; additionally failed to discard result workspace: injected scoped cleanup failure"
    );
    assert!(incoming.join("report.bin").is_file());
    assert!(
        workspace.is_none(),
        "failed discard relinquishes the handle"
    );
}

#[test]
fn local_candidate_requires_exact_cache_digest_and_job_owned_mapped_paths() {
    let root = tempfile::tempdir().expect("jobs root");
    let candidate_bytes = b"exact-candidate";
    let candidate_digest = format!("{:x}", sha2::Sha256::digest(candidate_bytes));
    let cache = root.path().join("run-local-cache");
    fs::create_dir(&cache).expect("candidate cache");
    let candidate_name = format!("sha256-{candidate_digest}.exe");
    let candidate_path = cache.join(&candidate_name);
    fs::write(&candidate_path, candidate_bytes).expect("candidate bytes");

    let run_id = "0123456789abcdef0123456789abcdef";
    let run_root = root.path().join("run-local-runs").join(run_id);
    fs::create_dir_all(run_root.join("mapped")).expect("prepared workspace");
    let mapped_digest = format!("{:x}", sha2::Sha256::digest(b"mapped-input"));
    let mapped_path = run_root
        .join("mapped")
        .join(format!("ONEC_INPUT-sha256-{mapped_digest}"));
    fs::write(&mapped_path, b"mapped-input").expect("mapped bytes");
    let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
        run_id.to_owned(),
        candidate_name.clone(),
        candidate_digest.clone(),
        vec![
            onec_agent_protocol::RunLocalMappedFile::try_new(
                "ONEC_INPUT".to_owned(),
                mapped_digest,
            )
            .expect("valid mapped identity"),
        ],
    )
    .expect("valid local identity");
    let env = BTreeMap::from([(
        "ONEC_INPUT".to_owned(),
        mapped_path.to_string_lossy().into_owned(),
    )]);
    workflow::validate_run_local_candidate(
        root.path(),
        &candidate_path.to_string_lossy(),
        Some(&run_root.to_string_lossy()),
        &env,
        &identity,
    )
    .expect("exact owned candidate and mapped input");
    assert!(
        onec_agent_protocol::RunLocalJobIdentity::try_new(
            run_id.to_owned(),
            format!("sha256-{candidate_digest};untrusted"),
            candidate_digest.clone(),
            Vec::new(),
        )
        .is_err()
    );

    assert!(
        workflow::validate_run_local_candidate(
            root.path(),
            &candidate_path.to_string_lossy(),
            Some("C:\\unowned"),
            &env,
            &identity,
        )
        .is_err()
    );

    let arbitrary = root.path().join("unowned.exe");
    fs::write(&arbitrary, candidate_bytes).expect("arbitrary executable");
    assert!(
        workflow::validate_run_local_candidate(
            root.path(),
            &arbitrary.to_string_lossy(),
            Some(&run_root.to_string_lossy()),
            &env,
            &identity,
        )
        .is_err()
    );
    fs::write(&mapped_path, b"altered-input").expect("tamper mapped bytes");
    assert!(
        workflow::validate_run_local_candidate(
            root.path(),
            &candidate_path.to_string_lossy(),
            Some(&run_root.to_string_lossy()),
            &env,
            &identity,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_worker_rejects_forged_argv_before_child_spawn() {
    let root = tempfile::tempdir().expect("jobs root");
    let run_id = "0123456789abcdef0123456789abcdef";
    let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
        run_id.to_owned(),
        format!("sha256-{}.exe", "a".repeat(64)),
        "a".repeat(64),
        Vec::new(),
    )
    .expect("valid run-local identity");
    let program = "candidate.exe".to_owned();
    let expected_args = vec!["--exact".to_owned(), "approved::test".to_owned()];
    let forged_args = vec!["--exact".to_owned(), "forged::passing_test".to_owned()];
    let cwd = Some("owned-root".to_owned());
    let env = BTreeMap::new();
    let stdin = None;
    let results = Vec::new();
    let effect = onec_agent_protocol::NativeExecutionEffect::ReadOnly;
    let expected_launch = JobRequestFile {
        version: JOB_SCHEMA_VERSION,
        program: program.clone(),
        args: expected_args,
        cwd: cwd.clone(),
        env: env.clone(),
        stdin: stdin.clone(),
        results: results.clone(),
        run_local: Some(identity.clone()),
        invocation_sha256: None,
        native_effect: Some(effect),
        native_suite_policy_sha256: None,
        native_suite_expected_tests: None,
    };
    let digest = workflow::invocation_sha256(&expected_launch).expect("expected invocation digest");
    let invocation_commitment =
        workflow::native_invocation_commitment(&expected_launch, digest.clone(), effect);
    assert_eq!(
        invocation_commitment.requested_exact_testcase.as_deref(),
        Some("approved::test")
    );
    let job_id = "job-forged-native-argv";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job directory");
    write_new_json_file(
        &job_dir.join("native-invocation.json"),
        &invocation_commitment,
    )
    .expect("persist immutable commitment");
    write_new_json_file(
        &job_dir.join("request.json"),
        &JobRequestFile {
            version: JOB_SCHEMA_VERSION,
            program,
            args: forged_args,
            cwd,
            env,
            stdin,
            results,
            run_local: Some(identity),
            invocation_sha256: Some(digest),
            native_effect: Some(effect),
            native_suite_policy_sha256: None,
            native_suite_expected_tests: None,
        },
    )
    .expect("persist tampered request");
    write_state(
        &job_dir,
        0,
        &AgentJobInfo {
            job_id: job_id.to_owned(),
            state: AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: unix_ms(),
            started_unix_ms: None,
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: None,
        },
    )
    .expect("queued state");

    let error = run_worker(&job_dir)
        .await
        .expect_err("worker must reject forged argv");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        read_latest_state(&job_dir).expect("state").state,
        AgentJobState::Queued
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_signs_worker_published_result_manifest_after_cleanup() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("jobs root");
    let run_id = "0123456789abcdef0123456789abcdef";
    let run_root = root.path().join("run-local-runs").join(run_id);
    ensure_private_directory(&run_root).expect("run root");
    let bytes = b"published fixture bytes";
    let script = format!(
        "#!/bin/sh\nprintf '{}' > \"$ONEC_RESULT_DIR/report.bin\"\nprintf worker-output\n",
        String::from_utf8_lossy(bytes)
    );
    let candidate_sha256 = format!("{:x}", sha2::Sha256::digest(script.as_bytes()));
    let candidate_name = format!("sha256-{candidate_sha256}.sh");
    let cache = root.path().join("run-local-cache");
    ensure_private_directory(&cache).expect("candidate cache");
    let candidate_path = cache.join(&candidate_name);
    fs::write(&candidate_path, script).expect("candidate script");
    fs::set_permissions(&candidate_path, fs::Permissions::from_mode(0o700))
        .expect("executable candidate");
    let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
        run_id.to_owned(),
        candidate_name,
        candidate_sha256,
        Vec::new(),
    )
    .expect("run-local identity");
    let job_id = "job-native-result-provenance";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job directory");
    let results = vec![
        onec_agent_protocol::ResultArtifactSpec::try_new(
            "report.bin".to_owned(),
            1024,
            Some("application/octet-stream".to_owned()),
        )
        .expect("result declaration"),
    ];
    let mut request = JobRequestFile {
        version: JOB_SCHEMA_VERSION,
        program: candidate_path.to_string_lossy().into_owned(),
        args: Vec::new(),
        cwd: Some(run_root.to_string_lossy().into_owned()),
        env: BTreeMap::new(),
        stdin: None,
        results,
        run_local: Some(identity.clone()),
        invocation_sha256: None,
        native_effect: Some(onec_agent_protocol::NativeExecutionEffect::ReadOnly),
        native_suite_policy_sha256: None,
        native_suite_expected_tests: None,
    };
    let invocation_sha256 = workflow::invocation_sha256(&request).expect("invocation digest");
    request.invocation_sha256 = Some(invocation_sha256.clone());
    write_new_json_file(&job_dir.join("request.json"), &request).expect("job request");
    write_new_json_file(
        &job_dir.join("native-invocation.json"),
        &NativeInvocationCommitment {
            version: 1,
            invocation_sha256: invocation_sha256.clone(),
            requested_exact_testcase: onec_agent_protocol::requested_exact_testcase(&request.args)
                .map(str::to_owned),
            native_effect: onec_agent_protocol::NativeExecutionEffect::ReadOnly,
            results: request.results.clone(),
        },
    )
    .expect("immutable invocation commitment");
    write_state(
        &job_dir,
        0,
        &AgentJobInfo {
            job_id: job_id.to_owned(),
            state: AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: unix_ms(),
            started_unix_ms: None,
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(identity),
        },
    )
    .expect("queued state");

    run_worker(&job_dir)
        .await
        .expect("run real result-producing worker");
    let terminal = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(
        terminal.state,
        AgentJobState::Succeeded,
        "{:?}",
        terminal.message
    );
    let manifest = terminal.result_set.clone().expect("published result set");
    assert_eq!(manifest.owner().job_id(), Some(job_id));
    assert_eq!(manifest.artifacts()[0].bytes(), bytes.len() as u64);
    assert_eq!(
        manifest.artifacts()[0].sha256(),
        format!("{:x}", sha2::Sha256::digest(bytes))
    );
    onec_core::remove_path_scoped(&job_dir, &job_dir.join("results"), true, false)
        .expect("simulate retrieved result cleanup");
    let terminal_state_path = fs::read_dir(&job_dir)
        .expect("job directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("state-"))
        })
        .max()
        .expect("terminal state file");
    let original_state = fs::read(&terminal_state_path).expect("terminal state bytes");
    let mut changed_state: serde_json::Value =
        serde_json::from_slice(&original_state).expect("terminal state JSON");
    changed_state["job"]["result_set"]["artifacts"][0]["sha256"] =
        serde_json::Value::String("f".repeat(64));
    fs::write(
        &terminal_state_path,
        serde_json::to_vec(&changed_state).expect("changed terminal state"),
    )
    .expect("tamper terminal result manifest");
    onec_core::restrict_private_file(&terminal_state_path).expect("keep state private");
    assert!(
        crate::native_attestation::observe_run_local_invocation(
            root.path(),
            job_id,
            &"c".repeat(64),
            &invocation_sha256,
        )
        .is_err()
    );
    fs::write(&terminal_state_path, &original_state).expect("restore terminal state");
    onec_core::restrict_private_file(&terminal_state_path).expect("keep state private");

    let seal_path = job_dir.join("native-output-logs.json");
    let original_seal = fs::read(&seal_path).expect("worker seal bytes");
    let mut changed_seal: serde_json::Value =
        serde_json::from_slice(&original_seal).expect("worker seal JSON");
    changed_seal["result_set"]["artifacts"][0]["sha256"] =
        serde_json::Value::String("e".repeat(64));
    fs::write(
        &seal_path,
        serde_json::to_vec(&changed_seal).expect("changed worker seal"),
    )
    .expect("tamper worker result seal");
    onec_core::restrict_private_file(&seal_path).expect("keep worker seal private");
    assert!(
        crate::native_attestation::observe_run_local_invocation(
            root.path(),
            job_id,
            &"c".repeat(64),
            &invocation_sha256,
        )
        .is_err()
    );
    fs::write(&seal_path, original_seal).expect("restore worker seal");
    onec_core::restrict_private_file(&seal_path).expect("keep worker seal private");

    let (record, _) = crate::native_attestation::observe_run_local_invocation(
        root.path(),
        job_id,
        &"c".repeat(64),
        &invocation_sha256,
    )
    .expect("sign published result provenance");
    assert_eq!(record.result_set.as_ref(), Some(&manifest));
    assert_eq!(
        record
            .result_set
            .as_ref()
            .expect("signed manifest")
            .owner()
            .job_id(),
        Some(job_id)
    );
    crate::native_attestation::fetch_run_local_invocation_observation(
        root.path(),
        job_id,
        &"c".repeat(64),
        &invocation_sha256,
    )
    .expect("read-only fetch after result cleanup");

    let state_path = terminal_state_path;
    let original_state = fs::read(&state_path).expect("terminal state bytes");
    let mut changed_state: serde_json::Value =
        serde_json::from_slice(&original_state).expect("terminal state JSON");
    changed_state["job"]["result_set"]["artifacts"][0]["sha256"] =
        serde_json::Value::String("d".repeat(64));
    fs::write(
        &state_path,
        serde_json::to_vec(&changed_state).expect("changed state JSON"),
    )
    .expect("tamper terminal result manifest");
    onec_core::restrict_private_file(&state_path).expect("keep state private");
    let seal_path = job_dir.join("native-output-logs.json");
    let original_seal = fs::read(&seal_path).expect("worker seal bytes");
    let mut changed_seal: serde_json::Value =
        serde_json::from_slice(&original_seal).expect("worker seal JSON");
    changed_seal["result_set"]["artifacts"][0]["sha256"] =
        serde_json::Value::String("d".repeat(64));
    fs::write(
        &seal_path,
        serde_json::to_vec(&changed_seal).expect("changed seal JSON"),
    )
    .expect("tamper worker result seal to match terminal state");
    onec_core::restrict_private_file(&seal_path).expect("keep worker seal private");
    assert!(
        crate::native_attestation::fetch_run_local_invocation_observation(
            root.path(),
            job_id,
            &"c".repeat(64),
            &invocation_sha256,
        )
        .is_err()
    );
}

#[test]
fn durable_local_status_reconnects_by_run_identity() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_dir = root.path().join("job-reconnect");
    create_private_directory(&job_dir).expect("job directory");
    let run_id = "0123456789abcdef0123456789abcdef";
    let job = AgentJobInfo {
        job_id: "job-reconnect".to_owned(),
        state: AgentJobState::Running,
        worker_pid: Some(std::process::id()),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: Some(
            onec_agent_protocol::RunLocalJobIdentity::try_new(
                run_id.to_owned(),
                format!("sha256-{}.exe", "a".repeat(64)),
                "a".repeat(64),
                Vec::new(),
            )
            .expect("valid run-local identity"),
        ),
    };
    write_state(&job_dir, 0, &job).expect("write durable metadata");
    assert_eq!(
        workflow::status_by_run_id(root.path(), run_id).expect("reconnect by run ID"),
        job
    );
    assert_eq!(
        workflow::status_by_run_id(root.path(), "1123456789abcdef0123456789abcdef")
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn run_id_lookup_skips_unrelated_control_locks_and_reconciles_match() {
    let root = tempfile::tempdir().expect("jobs root");
    let unrelated_dir = root.path().join("job-unrelated");
    create_private_directory(&unrelated_dir).expect("unrelated job directory");
    let unrelated_run_id = "0123456789abcdef0123456789abcdef";
    write_state(
        &unrelated_dir,
        0,
        &AgentJobInfo {
            job_id: "job-unrelated".to_owned(),
            state: AgentJobState::Succeeded,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: Some(0),
            created_unix_ms: 1,
            started_unix_ms: Some(2),
            finished_unix_ms: Some(3),
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(
                onec_agent_protocol::RunLocalJobIdentity::try_new(
                    unrelated_run_id.to_owned(),
                    format!("sha256-{}.exe", "a".repeat(64)),
                    "a".repeat(64),
                    Vec::new(),
                )
                .expect("valid run-local identity"),
            ),
        },
    )
    .expect("write unrelated state");
    let _unrelated_control =
        acquire_job_control_lock(&unrelated_dir).expect("hold unrelated job control lock");

    let matching_dir = root.path().join("job-matching");
    create_private_directory(&matching_dir).expect("matching job directory");
    let matching_run_id = "1123456789abcdef0123456789abcdef";
    write_state(
        &matching_dir,
        0,
        &AgentJobInfo {
            job_id: "job-matching".to_owned(),
            state: AgentJobState::Running,
            worker_pid: Some(i32::MAX as u32),
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: 1,
            started_unix_ms: Some(2),
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(
                onec_agent_protocol::RunLocalJobIdentity::try_new(
                    matching_run_id.to_owned(),
                    format!("sha256-{}.exe", "b".repeat(64)),
                    "b".repeat(64),
                    Vec::new(),
                )
                .expect("valid run-local identity"),
            ),
        },
    )
    .expect("write matching state");

    assert_eq!(
        workflow::status_by_run_id(root.path(), "2123456789abcdef0123456789abcdef")
            .expect_err("fresh run ID has no job")
            .kind(),
        io::ErrorKind::NotFound
    );
    let reconciled = workflow::status_by_run_id(root.path(), matching_run_id)
        .expect("matching job is reconciled through authoritative status");
    assert_eq!(reconciled.state, AgentJobState::Interrupted);
    assert!(reconciled.finished_unix_ms.is_some());
    assert_eq!(
        read_latest_state(&matching_dir)
            .expect("reconciled state persisted")
            .state,
        AgentJobState::Interrupted
    );
}

#[test]
fn run_id_lookup_reads_many_terminal_jobs_without_control_locks() {
    let root = tempfile::tempdir().expect("jobs root");
    let mut held_controls = Vec::new();
    for index in 0..32 {
        let job_id = format!("job-terminal-{index}");
        let job_dir = root.path().join(&job_id);
        create_private_directory(&job_dir).expect("terminal job directory");
        write_state(
            &job_dir,
            0,
            &AgentJobInfo {
                job_id,
                state: AgentJobState::Succeeded,
                worker_pid: None,
                spawn_owner_pid: None,
                process_pid: None,
                exit_code: Some(0),
                created_unix_ms: 1,
                started_unix_ms: Some(2),
                finished_unix_ms: Some(3),
                message: None,
                stdout_log_truncated: false,
                stderr_log_truncated: false,
                result_set: None,
                run_local: Some(
                    onec_agent_protocol::RunLocalJobIdentity::try_new(
                        format!("{index:032x}"),
                        format!("sha256-{}.exe", "c".repeat(64)),
                        "c".repeat(64),
                        Vec::new(),
                    )
                    .expect("valid run-local identity"),
                ),
            },
        )
        .expect("write terminal state");
        held_controls
            .push(acquire_job_control_lock(&job_dir).expect("hold terminal job control lock"));
    }

    assert_eq!(
        workflow::status_by_run_id(root.path(), "ffffffffffffffffffffffffffffffff")
            .expect_err("no terminal job matches")
            .kind(),
        io::ErrorKind::NotFound
    );
    drop(held_controls);
}

#[tokio::test]
async fn regression_inv_108_job_request_and_state_reject_oversized_files() {
    let dir = std::env::temp_dir().join(format!(
        "onec-agent-inv108-job-docs-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    fs::create_dir_all(&dir).expect("tempdir");
    fs::write(
        dir.join("request.json"),
        vec![b' '; JOB_REQUEST_MAX_BYTES + 1],
    )
    .expect("oversized request");
    let request_error = run_worker(&dir)
        .await
        .expect_err("oversized request must fail");
    assert_eq!(request_error.kind(), io::ErrorKind::InvalidData);

    fs::write(
        dir.join("state-000000.json"),
        vec![b' '; JOB_STATE_MAX_BYTES + 1],
    )
    .expect("oversized state");
    let state_error = read_latest_state(&dir).expect_err("oversized state must fail");
    assert_eq!(state_error.kind(), io::ErrorKind::InvalidData);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn regression_inv_069_streaming_log_redaction_handles_split_secret() {
    let dir = std::env::temp_dir().join(format!(
        "onec-agent-inv069-redaction-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    ensure_private_directory(&dir).expect("private tempdir");
    let path = dir.join("redacted.log");
    let mut writer =
        DurableJobLogSink::open(&path, vec![b"SECRET-VALUE".to_vec()]).expect("durable log sink");
    writer.write_chunk(b"prefix SECRET").expect("first chunk");
    writer.write_chunk(b"-VALUE suffix").expect("second chunk");
    writer.finish().expect("finish and sync");
    assert_eq!(
        fs::read_to_string(&path).expect("read log"),
        "prefix [REDACTED] suffix"
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[cfg(unix)]
fn queued_job(
    root: &Path,
    script: &str,
    stdin: Option<StdinPayload>,
    results: Vec<onec_agent_protocol::ResultArtifactSpec>,
) -> PathBuf {
    let job_dir = root.join("job-test");
    ensure_private_directory(&job_dir).expect("private job directory");
    let (program, args) = shell_command(script);
    write_new_json_file(
        &job_dir.join("request.json"),
        &JobRequestFile {
            version: JOB_SCHEMA_VERSION,
            program,
            args,
            cwd: None,
            env: BTreeMap::new(),
            stdin,
            results,
            run_local: None,
            invocation_sha256: None,
            native_effect: None,
            native_suite_policy_sha256: None,
            native_suite_expected_tests: None,
        },
    )
    .expect("write job request");
    write_state(
        &job_dir,
        0,
        &AgentJobInfo {
            job_id: "job-test".to_owned(),
            state: AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: unix_ms(),
            started_unix_ms: None,
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: None,
        },
    )
    .expect("write queued state");
    job_dir
}

#[cfg(unix)]
fn shell_command(script: &str) -> (String, Vec<String>) {
    ("sh".to_owned(), vec!["-c".to_owned(), script.to_owned()])
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
async fn wait_for_worker_pid(job_dir: &Path) -> u32 {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(state) = read_latest_state(job_dir)
                && let Some(pid) = state.process_pid
            {
                return pid;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker process PID publication")
}

#[cfg(unix)]
async fn wait_for_terminal(job_dir: &Path) -> AgentJobInfo {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = read_latest_state(job_dir).expect("read latest durable state");
            if state.state.is_terminal() {
                return state;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("terminal job state")
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_worker_commits_digests_of_its_finalized_output_logs() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("jobs root");
    let run_id = "0123456789abcdef0123456789abcdef".to_owned();
    let run_root = root.path().join("run-local-runs").join(&run_id);
    ensure_private_directory(&run_root).expect("run-local workspace");
    let candidate_bytes = b"#!/bin/sh\nprintf stdout-bytes\nprintf stderr-bytes >&2\n";
    let candidate_sha256 = format!("{:x}", sha2::Sha256::digest(candidate_bytes));
    let candidate_name = format!("sha256-{candidate_sha256}.sh");
    let candidate_dir = root.path().join("run-local-cache");
    ensure_private_directory(&candidate_dir).expect("candidate cache");
    let candidate_path = candidate_dir.join(&candidate_name);
    fs::write(&candidate_path, candidate_bytes).expect("candidate script");
    fs::set_permissions(&candidate_path, fs::Permissions::from_mode(0o700))
        .expect("executable candidate");
    let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
        run_id,
        candidate_name,
        candidate_sha256,
        Vec::new(),
    )
    .expect("run-local identity");
    let job_id = "job-native-output-commitment";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job directory");
    let mut request = JobRequestFile {
        version: JOB_SCHEMA_VERSION,
        program: candidate_path.to_string_lossy().into_owned(),
        args: Vec::new(),
        cwd: Some(run_root.to_string_lossy().into_owned()),
        env: BTreeMap::new(),
        stdin: None,
        results: Vec::new(),
        run_local: Some(identity.clone()),
        invocation_sha256: None,
        native_effect: Some(onec_agent_protocol::NativeExecutionEffect::ReadOnly),
        native_suite_policy_sha256: None,
        native_suite_expected_tests: None,
    };
    let invocation_sha256 = workflow::invocation_sha256(&request).expect("invocation digest");
    request.invocation_sha256 = Some(invocation_sha256.clone());
    write_new_json_file(&job_dir.join("request.json"), &request).expect("job request");
    write_new_json_file(
        &job_dir.join("native-invocation.json"),
        &NativeInvocationCommitment {
            version: 1,
            invocation_sha256: invocation_sha256.clone(),
            requested_exact_testcase: onec_agent_protocol::requested_exact_testcase(&request.args)
                .map(str::to_owned),
            native_effect: onec_agent_protocol::NativeExecutionEffect::ReadOnly,
            results: request.results.clone(),
        },
    )
    .expect("immutable invocation commitment");
    write_state(
        &job_dir,
        0,
        &AgentJobInfo {
            job_id: job_id.to_owned(),
            state: AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: unix_ms(),
            started_unix_ms: None,
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(identity),
        },
    )
    .expect("queued state");

    run_worker(&job_dir)
        .await
        .expect("native invocation worker");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Succeeded, "{:?}", state.message);
    let expected = crate::native_attestation::read_completed_invocation_output_logs(
        root.path(),
        &state,
        &invocation_sha256,
    )
    .expect("worker completion commitment");
    assert_eq!(
        fs::read(job_dir.join("stdout.log")).expect("stdout"),
        b"stdout-bytes"
    );
    assert_eq!(
        fs::read(job_dir.join("stderr.log")).expect("stderr"),
        b"stderr-bytes"
    );
    assert_eq!(expected.stdout_bytes, b"stdout-bytes".len() as u64);
    assert_eq!(expected.stderr_bytes, b"stderr-bytes".len() as u64);
    assert_eq!(
        expected.stdout_sha256,
        format!("{:x}", sha2::Sha256::digest(b"stdout-bytes"))
    );
    assert_eq!(
        expected.stderr_sha256,
        format!("{:x}", sha2::Sha256::digest(b"stderr-bytes"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_preserves_exact_stdin_and_terminal_exit_semantics() {
    let root = tempfile::tempdir().expect("tempdir");
    let payload = vec![0x00, b'A', 0xff, b'\r', b'\n'];
    let job_dir = queued_job(
        root.path(),
        "cat",
        Some(StdinPayload::try_new(payload.clone()).expect("bounded stdin")),
        Vec::new(),
    );

    run_worker(&job_dir).await.expect("run successful job");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Succeeded);
    assert_eq!(state.exit_code, Some(0));
    assert!(state.worker_pid.is_some());
    assert!(state.process_pid.is_some());
    assert!(!job_dir.join("request.json").exists());
    assert_eq!(
        fs::read(job_dir.join("stdout.log")).expect("stdout log"),
        payload
    );

    let failed_root = tempfile::tempdir().expect("failed tempdir");
    let failed_dir = queued_job(
        failed_root.path(),
        "printf failed; exit 7",
        None,
        Vec::new(),
    );
    run_worker(&failed_dir).await.expect("run nonzero job");
    let failed = read_latest_state(&failed_dir).expect("failed terminal state");
    assert_eq!(failed.state, AgentJobState::Failed);
    assert_eq!(failed.exit_code, Some(7));
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_cancellation_reaps_the_tree_before_publishing_terminal_state() {
    let root = tempfile::tempdir().expect("tempdir");
    let marker = root.path().join("descendant-survived");
    let script = format!(
        "sleep 1; printf survived > {}",
        shell_quote(&marker.to_string_lossy())
    );
    let job_dir = queued_job(root.path(), &script, None, Vec::new());
    let worker_dir = job_dir.clone();
    let worker = tokio::spawn(async move { run_worker(&worker_dir).await });

    let process_pid = wait_for_worker_pid(&job_dir).await;
    assert!(
        !job_dir.join("request.json").exists(),
        "worker ownership state is durable before request deletion"
    );
    write_new_private_bytes(&job_dir.join("cancel.request"), b"cancel\n")
        .expect("request cancellation");
    worker
        .await
        .expect("worker task join")
        .expect("worker result");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Canceled);
    assert_eq!(state.process_pid, Some(process_pid));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        !marker.exists(),
        "a descendant must not outlive the canceled worker tree"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_waits_for_silent_descendant_before_terminal_state() {
    let root = tempfile::tempdir().expect("tempdir");
    let marker = root.path().join("descendant-finished");
    let script = format!(
        "(sleep 0.3; printf done > {}) >/dev/null 2>&1 & exit 0",
        shell_quote(&marker.to_string_lossy())
    );
    let job_dir = queued_job(root.path(), &script, None, Vec::new());

    run_worker(&job_dir).await.expect("run descendant job");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Succeeded);
    assert!(
        marker.exists(),
        "terminal success must wait for the complete owned process tree"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_log_open_failure_prevents_terminal_success() {
    let root = tempfile::tempdir().expect("tempdir");
    let job_dir = queued_job(root.path(), "printf output; sleep 1", None, Vec::new());
    fs::create_dir(job_dir.join("stdout.log")).expect("block stdout log path");

    let result = run_worker(&job_dir).await;

    assert!(
        result.is_ok(),
        "confirmed durable log failure should publish Failed"
    );
    let state = read_latest_state(&job_dir).expect("durable state");
    assert_eq!(
        state.state,
        AgentJobState::Failed,
        "a failed log sink must publish terminal failure after confirmed completion"
    );
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("failed to persist durable")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_log_failure_overrides_requested_cancellation_after_confirmed_teardown() {
    let root = tempfile::tempdir().expect("tempdir");
    let job_dir = queued_job(root.path(), "printf output; sleep 1", None, Vec::new());
    fs::create_dir(job_dir.join("stdout.log")).expect("block stdout log path");
    write_new_private_bytes(&job_dir.join("cancel.request"), b"cancel\n")
        .expect("durable cancellation marker");

    run_worker(&job_dir)
        .await
        .expect("confirmed log failure should publish terminal state");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Failed);
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("failed to persist durable"),
        "fail-visible durable log error must not degrade to canceled/interrupted"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_reports_stdin_pipe_failure_as_failed_state() {
    let root = tempfile::tempdir().expect("tempdir");
    let payload = vec![b'x'; onec_agent_protocol::MAX_STDIN_PAYLOAD_BYTES];
    let job_dir = queued_job(
        root.path(),
        "exec 0<&-; sleep 1; exit 0",
        Some(StdinPayload::try_new(payload).expect("maximum stdin payload")),
        Vec::new(),
    );

    run_worker(&job_dir)
        .await
        .expect("worker records stdin failure");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Failed);
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("stdin")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_preserves_stdin_failure_when_child_exits_nonzero() {
    let root = tempfile::tempdir().expect("tempdir");
    let payload = vec![b'x'; onec_agent_protocol::MAX_STDIN_PAYLOAD_BYTES];
    let job_dir = queued_job(
        root.path(),
        "exec 0<&-; sleep 0.2; exit 7",
        Some(StdinPayload::try_new(payload).expect("maximum stdin payload")),
        Vec::new(),
    );

    run_worker(&job_dir)
        .await
        .expect("worker records stdin failure");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Failed);
    assert_eq!(state.exit_code, Some(7));
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("stdin"),
        "stdin delivery failure must remain visible even when the child exits nonzero"
    );
}

#[test]
fn interrupted_status_preserves_workspace_even_with_forgeable_child_marker() {
    let root = tempfile::tempdir().expect("tempdir");
    let job_id = "job-interrupted-unconfirmed-tree";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job dir");
    let running = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Running,
        worker_pid: Some(i32::MAX as u32),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    write_state(&job_dir, 0, &running).expect("running state");
    let workspace = crate::results::ResultWorkspace::prepare_job(
        &job_dir,
        job_id,
        &[onec_agent_protocol::ResultArtifactSpec::try_new(
            "report.bin".to_owned(),
            64,
            Some("application/octet-stream".to_owned()),
        )
        .expect("valid result declaration")],
    )
    .expect("prepare result workspace")
    .expect("non-empty workspace");
    let incoming = workspace.incoming_path().to_owned();
    fs::write(incoming.join("report.bin"), b"partial-result").expect("partial result");
    drop(workspace);
    fs::write(job_dir.join("tree-exit.confirmed"), b"forged-by-child\n")
        .expect("forgeable child-visible marker");

    let state = workflow::status(root.path(), job_id).expect("interrupted status");

    assert_eq!(state.state, AgentJobState::Interrupted);
    assert!(
        incoming.join("report.bin").is_file(),
        "worker death must preserve unpublished workspace even if a child-visible marker exists"
    );
}

#[test]
fn queued_job_without_live_worker_or_spawn_owner_recovers_as_failed() {
    let root = tempfile::tempdir().expect("tempdir");
    let job_id = "job-orphaned-before-worker-spawn";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job dir");
    let mut queued = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Queued,
        worker_pid: None,
        spawn_owner_pid: Some(i32::MAX as u32),
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: None,
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: Some(
            onec_agent_protocol::RunLocalJobIdentity::try_new(
                "0123456789abcdef0123456789abcdef".to_owned(),
                format!("sha256-{}.exe", "a".repeat(64)),
                "a".repeat(64),
                Vec::new(),
            )
            .expect("valid run-local identity"),
        ),
    };
    write_state(&job_dir, 0, &queued).expect("queued state");
    fs::write(job_dir.join("request.json"), b"private launch request")
        .expect("orphaned launch request");

    workflow::recover_stale_jobs(root.path()).expect("startup recovers orphaned queue");
    let recovered = workflow::status(root.path(), job_id).expect("read recovered state");

    assert_eq!(recovered.state, AgentJobState::Failed);
    assert!(recovered.finished_unix_ms.is_some());
    assert!(
        recovered
            .message
            .as_deref()
            .is_some_and(|message| message.contains("before a worker was started"))
    );
    assert!(!job_dir.join("request.json").exists());

    let spawned_but_never_started_id = "job-recorded-worker-never-started";
    let spawned_but_never_started_dir = root.path().join(spawned_but_never_started_id);
    ensure_private_directory(&spawned_but_never_started_dir).expect("spawned job dir");
    queued.job_id = spawned_but_never_started_id.to_owned();
    queued.spawn_owner_pid = None;
    queued.worker_pid = Some(i32::MAX as u32);
    write_state(&spawned_but_never_started_dir, 0, &queued).expect("queued worker state");
    workflow::recover_stale_jobs(root.path()).expect("startup recovers dead worker launch");
    assert_eq!(
        workflow::status(root.path(), spawned_but_never_started_id)
            .expect("read terminal launch failure")
            .state,
        AgentJobState::Failed
    );

    let live_job_id = "job-live-launch-owner";
    let live_dir = root.path().join(live_job_id);
    ensure_private_directory(&live_dir).expect("live job dir");
    queued.job_id = live_job_id.to_owned();
    queued.worker_pid = None;
    queued.spawn_owner_pid = Some(std::process::id());
    write_state(&live_dir, 0, &queued).expect("live queued state");
    assert_eq!(
        workflow::status(root.path(), live_job_id)
            .expect("live launch remains queued")
            .state,
        AgentJobState::Queued
    );
}

#[test]
fn legacy_pid_only_job_state_is_readable_and_reconciled_without_signaling_its_pid() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_id = "job-legacy-pid-only";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job dir");
    let running = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Running,
        worker_pid: Some(std::process::id()),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    let legacy = serde_json::json!({ "version": JOB_SCHEMA_VERSION, "job": running });
    fs::write(
        job_dir.join("state-000000.json"),
        serde_json::to_vec(&legacy).expect("legacy state JSON"),
    )
    .expect("legacy PID-only state");

    let record = read_latest_state_file(&job_dir).expect("legacy state remains readable");
    assert!(record.process_identities.worker.is_none());
    let status_error = workflow::status(root.path(), job_id)
        .expect_err("an existing PID-only owner cannot safely be called dead or alive");
    assert_eq!(status_error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        read_latest_state(&job_dir)
            .expect("legacy state remains untouched")
            .state,
        AgentJobState::Running
    );
    assert!(ProcessIdentity::capture(std::process::id()).is_some());
    let current_identity =
        ProcessIdentity::capture(std::process::id()).expect("current process identity");
    assert!(
        current_identity.status() == ProcessStatus::Alive,
        "reconciliation must not signal or terminate the unrelated PID-only process"
    );

    let exited_id = "job-legacy-pid-only-exited";
    let exited_dir = root.path().join(exited_id);
    ensure_private_directory(&exited_dir).expect("exited legacy job dir");
    let exited = AgentJobInfo {
        job_id: exited_id.to_owned(),
        worker_pid: Some(i32::MAX as u32),
        ..read_latest_state(&job_dir).expect("original legacy state")
    };
    let exited_record = serde_json::json!({ "version": JOB_SCHEMA_VERSION, "job": exited });
    fs::write(
        exited_dir.join("state-000000.json"),
        serde_json::to_vec(&exited_record).expect("exited legacy JSON"),
    )
    .expect("exited legacy state");
    workflow::recover_stale_jobs(root.path()).expect("preserve ambiguous, recover absent PID");
    assert_eq!(
        read_latest_state(&exited_dir)
            .expect("recovered exited legacy state")
            .state,
        AgentJobState::Interrupted
    );
}

#[test]
fn missing_versioned_identity_reconciles_only_after_pid_is_confirmed_absent() {
    assert_eq!(
        workflow::process_status(Some(i32::MAX as u32), None, 1),
        ProcessStatus::Dead,
        "an absent PID cannot belong to the original worker"
    );
    assert_eq!(
        workflow::process_status(Some(std::process::id()), None, 1),
        ProcessStatus::Unverifiable,
        "an existing PID without a creation token must never establish ownership"
    );
}

#[test]
fn worker_startup_publishes_its_identity_when_parent_snapshot_lacked_one() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_id = "job-worker-start-identity-order";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job dir");
    let queued = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Queued,
        worker_pid: Some(std::process::id()),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: None,
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    state::write_state_with_identities(
        &job_dir,
        0,
        &queued,
        JobProcessIdentities {
            version: 1,
            worker: None,
            spawn_owner: None,
            process: None,
        },
    )
    .expect("queued PID-only startup snapshot");

    let mut running = queued;
    running.state = AgentJobState::Running;
    running.started_unix_ms = Some(2);
    write_next_state(&job_dir, &running).expect("worker ownership snapshot");

    let record = read_latest_state_file(&job_dir).expect("running worker identity");
    assert_eq!(
        record
            .process_identities
            .worker
            .as_ref()
            .map(|identity| identity.pid),
        Some(std::process::id())
    );
}

#[cfg(unix)]
#[test]
fn worker_restart_reconciliation_uses_the_exited_workers_creation_identity() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_id = "job-worker-restart-identity";
    let job_dir = root.path().join(job_id);
    ensure_private_directory(&job_dir).expect("job dir");
    let mut worker = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn process representing detached worker");
    let worker_pid = worker.id();
    let running = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Running,
        worker_pid: Some(worker_pid),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    write_state(&job_dir, 0, &running).expect("persist process identity");
    assert_eq!(
        read_latest_state_file(&job_dir)
            .expect("durable worker state")
            .process_identities
            .worker
            .as_ref()
            .map(|identity| identity.pid),
        Some(worker_pid)
    );
    worker.kill().expect("stop test worker");
    worker.wait().expect("reap test worker");

    workflow::recover_stale_jobs(root.path()).expect("restart recovery");
    assert_eq!(
        workflow::status(root.path(), job_id)
            .expect("recovered state")
            .state,
        AgentJobState::Interrupted
    );
}

#[cfg(unix)]
fn queued_run_local_invocation(
    jobs_root: &Path,
    job_id: &str,
    script: &[u8],
    mapped_inputs: &[(&str, &[u8])],
    results: Vec<onec_agent_protocol::ResultArtifactSpec>,
) -> (String, PathBuf, Vec<PathBuf>) {
    use std::os::unix::fs::PermissionsExt;

    let run_id = "0123456789abcdef0123456789abcdef";
    let run_parent = jobs_root.join("run-local-runs");
    ensure_private_directory(&run_parent).expect("run parent");
    let run_root = run_parent.join(run_id);
    ensure_private_directory(&run_root).expect("run root");
    let candidate_sha256 = format!("{:x}", sha2::Sha256::digest(script));
    let candidate_name = format!("sha256-{candidate_sha256}.sh");
    let cache = jobs_root.join("run-local-cache");
    ensure_private_directory(&cache).expect("candidate cache");
    let candidate_path = cache.join(&candidate_name);
    fs::write(&candidate_path, script).expect("candidate script");
    fs::set_permissions(&candidate_path, fs::Permissions::from_mode(0o700))
        .expect("executable candidate");
    let identity = onec_agent_protocol::RunLocalJobIdentity::try_new(
        run_id.to_owned(),
        candidate_name,
        candidate_sha256.clone(),
        mapped_inputs
            .iter()
            .map(|(environment_name, bytes)| {
                let sha256 = format!("{:x}", sha2::Sha256::digest(bytes));
                onec_agent_protocol::RunLocalMappedFile::try_new(
                    (*environment_name).to_owned(),
                    sha256,
                )
                .expect("mapped file identity")
            })
            .collect(),
    )
    .expect("run-local identity");
    let mapped_root = run_root.join("mapped");
    if !mapped_inputs.is_empty() {
        ensure_private_directory(&mapped_root).expect("mapped input root");
    }
    let mut env = BTreeMap::new();
    let mapped_paths = mapped_inputs
        .iter()
        .map(|(environment_name, bytes)| {
            let sha256 = format!("{:x}", sha2::Sha256::digest(bytes));
            let path = mapped_root.join(format!("{environment_name}-sha256-{sha256}"));
            fs::write(&path, bytes).expect("mapped input bytes");
            env.insert(
                (*environment_name).to_owned(),
                path.to_string_lossy().into_owned(),
            );
            path
        })
        .collect();
    let mut request = JobRequestFile {
        version: JOB_SCHEMA_VERSION,
        program: candidate_path.to_string_lossy().into_owned(),
        args: Vec::new(),
        cwd: Some(run_root.to_string_lossy().into_owned()),
        env,
        stdin: None,
        results,
        run_local: Some(identity.clone()),
        invocation_sha256: None,
        native_effect: Some(onec_agent_protocol::NativeExecutionEffect::ReadOnly),
        native_suite_policy_sha256: None,
        native_suite_expected_tests: None,
    };
    let invocation_sha256 = workflow::invocation_sha256(&request).expect("invocation digest");
    request.invocation_sha256 = Some(invocation_sha256.clone());
    let job_dir = jobs_root.join(job_id);
    ensure_private_directory(&job_dir).expect("job directory");
    write_new_json_file(&job_dir.join("request.json"), &request).expect("job request");
    write_new_json_file(
        &job_dir.join("native-invocation.json"),
        &NativeInvocationCommitment {
            version: 1,
            invocation_sha256: invocation_sha256.clone(),
            requested_exact_testcase: onec_agent_protocol::requested_exact_testcase(&request.args)
                .map(str::to_owned),
            native_effect: onec_agent_protocol::NativeExecutionEffect::ReadOnly,
            results: request.results.clone(),
        },
    )
    .expect("immutable invocation commitment");
    write_state(
        &job_dir,
        0,
        &AgentJobInfo {
            job_id: job_id.to_owned(),
            state: AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: unix_ms(),
            started_unix_ms: None,
            finished_unix_ms: None,
            message: None,
            stdout_log_truncated: false,
            stderr_log_truncated: false,
            result_set: None,
            run_local: Some(identity),
        },
    )
    .expect("queued state");

    (invocation_sha256, candidate_path, mapped_paths)
}

#[cfg(unix)]
#[tokio::test]
async fn native_suite_inventory_tamper_fails_owned_job_before_any_runner_launch() {
    let root = tempfile::tempdir().expect("jobs root");
    let job_id = "job-native-suite-inventory-tamper";
    let marker = root.path().join("runner-launched");
    let script = format!("#!/bin/sh\nprintf launched > '{}'\n", marker.display());
    let (_, candidate_path, _) =
        queued_run_local_invocation(root.path(), job_id, script.as_bytes(), &[], Vec::new());
    let job_dir = root.path().join(job_id);
    let mut request: JobRequestFile =
        read_json_file_bounded(&job_dir.join("request.json"), JOB_REQUEST_MAX_BYTES)
            .expect("read admitted request");
    request.args = vec!["--approved-suite-args".to_owned()];
    let expected_tests = vec!["suite::case".to_owned()];
    let policy = onec_agent_protocol::NativeSuitePolicy {
        version: 1,
        runner_sha256: request
            .run_local
            .as_ref()
            .expect("run-local identity")
            .candidate_sha256()
            .to_owned(),
        args: request.args.clone(),
        env: request.env.clone(),
        expected_tests: expected_tests.clone(),
        effect: onec_agent_protocol::NativeExecutionEffect::ReadOnly,
    };
    request.native_suite_policy_sha256 = Some(policy.sha256().expect("canonical policy digest"));
    request.native_suite_expected_tests = Some(expected_tests);
    let invocation_sha256 = workflow::invocation_sha256(&request).expect("invocation digest");
    request.invocation_sha256 = Some(invocation_sha256.clone());
    fs::write(
        job_dir.join("request.json"),
        serde_json::to_vec(&request).expect("serialize admitted request"),
    )
    .expect("persist admitted suite request");
    fs::write(
        job_dir.join("native-invocation.json"),
        serde_json::to_vec(&workflow::native_invocation_commitment(
            &request,
            invocation_sha256.clone(),
            onec_agent_protocol::NativeExecutionEffect::ReadOnly,
        ))
        .expect("serialize immutable invocation commitment"),
    )
    .expect("persist invocation commitment");

    // Simulate changing only the durable inventory after admission; retain the approved digest,
    // runner identity, launch fields, invocation hash, and immutable invocation commitment.
    request.native_suite_expected_tests = Some(vec!["suite::forged_case".to_owned()]);
    fs::write(
        job_dir.join("request.json"),
        serde_json::to_vec(&request).expect("serialize tampered request"),
    )
    .expect("persist only the inventory tamper");
    assert_eq!(
        workflow::invocation_sha256(&request).expect("legacy invocation commitment remains"),
        invocation_sha256,
        "the suite-policy integrity check must protect the separate inventory field"
    );

    run_worker(&job_dir)
        .await
        .expect("worker durably fails the tampered owned job");

    let failed = read_latest_state(&job_dir).expect("failed job state");
    assert_eq!(failed.state, AgentJobState::Failed);
    assert!(failed.finished_unix_ms.is_some());
    assert!(
        failed
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("approved digest")
    );
    assert!(!marker.exists(), "no list or test process may launch");
    assert!(!job_dir.join("stdout.log").exists());
    assert_eq!(
        onec_core::sha256_file(&candidate_path).expect("pinned runner remains unchanged"),
        request
            .run_local
            .as_ref()
            .expect("run-local identity")
            .candidate_sha256()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_rejects_candidate_changed_by_successful_process() {
    let root = tempfile::tempdir().expect("jobs root");
    let results = vec![
        onec_agent_protocol::ResultArtifactSpec::try_new(
            "report.xml".to_owned(),
            1024,
            Some("application/xml".to_owned()),
        )
        .expect("result declaration"),
    ];
    let job_id = "job-candidate-mutated-during-run";
    let script =
        b"#!/bin/sh\nprintf changed > \"$0\"\nprintf junit > \"$ONEC_RESULT_DIR/report.xml\"\n";
    let candidate_sha256 = format!("{:x}", sha2::Sha256::digest(script));
    let (invocation_sha256, candidate_path, _) =
        queued_run_local_invocation(root.path(), job_id, script, &[], results);

    run_worker(&root.path().join(job_id))
        .await
        .expect("worker publishes the failed candidate-integrity outcome");

    let terminal = read_latest_state(&root.path().join(job_id)).expect("terminal state");
    assert_eq!(terminal.state, AgentJobState::Failed);
    assert_eq!(terminal.exit_code, Some(0));
    assert!(terminal.result_set.is_none());
    assert!(
        terminal
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("executable or mapped input changed during execution")
    );
    assert_ne!(
        onec_core::sha256_file(&candidate_path).expect("changed candidate digest"),
        candidate_sha256
    );
    assert!(
        crate::native_attestation::observe_run_local_invocation(
            root.path(),
            job_id,
            &"a".repeat(64),
            &invocation_sha256,
        )
        .is_err(),
        "changed executable must not receive a successful signed invocation"
    );
    assert!(!root.path().join("native-attestation-v1").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn native_invocation_rejects_mapped_file_changed_by_successful_process() {
    let root = tempfile::tempdir().expect("jobs root");
    let results = vec![
        onec_agent_protocol::ResultArtifactSpec::try_new(
            "report.xml".to_owned(),
            1024,
            Some("application/xml".to_owned()),
        )
        .expect("result declaration"),
    ];
    let job_id = "job-mapped-file-mutated-during-run";
    let (invocation_sha256, candidate_path, mapped_paths) = queued_run_local_invocation(
        root.path(),
        job_id,
        b"#!/bin/sh\nprintf changed > \"$ONEC_SUPPORT_FILE\"\nprintf junit > \"$ONEC_RESULT_DIR/report.xml\"\n",
        &[("ONEC_SUPPORT_FILE", b"approved support bytes")],
        results,
    );
    let original_candidate_sha256 =
        onec_core::sha256_file(&candidate_path).expect("candidate digest before run");
    let mapped_path = mapped_paths.first().expect("mapped support file");
    let original_mapped_sha256 = onec_core::sha256_file(mapped_path).expect("mapped digest");
    let mapped_path_text = mapped_path.to_string_lossy().into_owned();

    run_worker(&root.path().join(job_id))
        .await
        .expect("worker publishes the failed mapped-integrity outcome");

    let terminal = read_latest_state(&root.path().join(job_id)).expect("terminal state");
    assert_eq!(terminal.state, AgentJobState::Failed);
    assert_eq!(terminal.exit_code, Some(0));
    assert!(terminal.result_set.is_none());
    let message = terminal.message.as_deref().unwrap_or_default();
    assert!(message.contains("executable or mapped input changed during execution"));
    assert!(
        !message.contains(&mapped_path_text),
        "postflight error must not expose mapped paths"
    );
    assert!(
        !message.contains("approved support bytes"),
        "postflight error must not expose mapped file contents"
    );
    assert_eq!(
        onec_core::sha256_file(&candidate_path).expect("candidate digest after run"),
        original_candidate_sha256,
        "the executable must remain unchanged to isolate mapped-file validation"
    );
    assert_ne!(
        onec_core::sha256_file(mapped_path).expect("mutated mapped digest"),
        original_mapped_sha256
    );
    assert!(
        crate::native_attestation::observe_run_local_invocation(
            root.path(),
            job_id,
            &"b".repeat(64),
            &invocation_sha256,
        )
        .is_err(),
        "a mapped-file integrity failure must not receive a successful signed invocation"
    );
    assert!(!root.path().join("native-attestation-v1").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_supervises_and_finalizes_result_workspace_before_terminal_state() {
    let root = tempfile::tempdir().expect("tempdir");
    let spec = onec_agent_protocol::ResultArtifactSpec::try_new(
        "report.bin".to_owned(),
        64,
        Some("application/octet-stream".to_owned()),
    )
    .expect("valid result spec");
    let script = "printf artifact > \"$ONEC_RESULT_DIR/report.bin\"";
    let job_dir = queued_job(root.path(), script, None, vec![spec.clone()]);

    run_worker(&job_dir)
        .await
        .expect("run result-producing job");

    let state = read_latest_state(&job_dir).expect("terminal state");
    assert_eq!(state.state, AgentJobState::Succeeded);
    let result_set = state.result_set.expect("published result set");
    assert_eq!(result_set.artifacts().len(), 1);
    assert!(job_dir.join("results/manifest.json").is_file());

    let missing_root = tempfile::tempdir().expect("missing result tempdir");
    let missing = queued_job(missing_root.path(), "exit 0", None, vec![spec]);
    run_worker(&missing)
        .await
        .expect("worker records finalize error");
    let state = read_latest_state(&missing).expect("failed result state");
    assert_eq!(state.state, AgentJobState::Failed);
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("publish result artifacts")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_rejects_undeclared_result_while_child_is_running() {
    let root = tempfile::tempdir().expect("tempdir");
    let spec = onec_agent_protocol::ResultArtifactSpec::try_new("report.bin".to_owned(), 64, None)
        .expect("valid result spec");
    let job_dir = queued_job(
        root.path(),
        "printf bad > \"$ONEC_RESULT_DIR/undeclared.bin\"; sleep 2",
        None,
        vec![spec],
    );

    run_worker(&job_dir)
        .await
        .expect("worker records policy violation");

    let state = read_latest_state(&job_dir).expect("failed result state");
    assert_eq!(state.state, AgentJobState::Failed);
    assert!(
        state
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("policy violation")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn durable_worker_continues_after_observer_disconnect() {
    let root = tempfile::tempdir().expect("tempdir");
    let job_dir = queued_job(root.path(), "sleep 0.2; printf done", None, Vec::new());
    let worker_dir = job_dir.clone();
    let detached_worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("worker runtime")
            .block_on(run_worker(&worker_dir))
    });
    drop(detached_worker);

    let state = wait_for_terminal(&job_dir).await;
    assert_eq!(state.state, AgentJobState::Succeeded);
    assert_eq!(
        fs::read(job_dir.join("stdout.log")).expect("durable stdout"),
        b"done"
    );
}

#[test]
fn durable_worker_source_has_no_synchronous_process_polling() {
    let source = include_str!("workflow.rs");
    assert!(!source.contains("AsyncOwnedProcess"));
    assert!(!source.contains("OwnedProcess"));
    assert!(!source.contains("try_wait"));
    assert!(!source.contains("thread::sleep"));
}

#[test]
fn bounded_durable_log_keeps_latest_two_segments_and_marks_history_loss() {
    let dir = std::env::temp_dir().join(format!(
        "onec-agent-bounded-log-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    ensure_private_directory(&dir).expect("private tempdir");
    let path = dir.join("stdout.log");
    let log = RetainedLog::new(&path).expect("retained log");
    let mut writer = log.writer(JOB_LOG_SEGMENT_BYTES).expect("bounded log");
    let segment = vec![b'A'; JOB_LOG_SEGMENT_BYTES as usize];
    writer.write_all(&segment).expect("first segment");
    let segment = vec![b'B'; JOB_LOG_SEGMENT_BYTES as usize];
    writer.write_all(&segment).expect("second segment");
    writer.write_all(b"TAIL").expect("third segment start");
    writer.sync_all().expect("sync");
    drop(writer);

    let previous = dir.join("stdout.log.1");
    let marker = dir.join("stdout.truncated");
    assert_eq!(
        fs::metadata(&previous).expect("previous metadata").len(),
        JOB_LOG_SEGMENT_BYTES
    );
    assert_eq!(fs::metadata(&path).expect("active metadata").len(), 4);
    assert!(marker.is_file());
    assert!(
        fs::metadata(&previous).unwrap().len() + fs::metadata(&path).unwrap().len()
            <= MAX_DURABLE_JOB_LOG_BYTES
    );

    let tail = log.read_tail(16).expect("bounded tail");
    assert_eq!(
        String::from_utf8_lossy(&tail.bytes),
        format!("{}TAIL", "B".repeat(12))
    );
    assert!(tail.truncated);
    assert!(tail.storage_truncated);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn bounded_log_truncation_is_exposed_on_job_status() {
    let dir = std::env::temp_dir().join(format!(
        "onec-agent-bounded-status-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    fs::create_dir_all(&dir).expect("tempdir");
    ensure_private_directory(&dir).expect("private tempdir");
    write_new_private_bytes(&dir.join("stdout.truncated"), b"truncated\n").expect("marker");
    let mut job = AgentJobInfo {
        job_id: "job-test".to_owned(),
        state: AgentJobState::Succeeded,
        worker_pid: None,
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: Some(0),
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: Some(3),
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    apply_log_truncation_flags(&dir, &mut job).expect("apply flags");
    assert!(job.stdout_log_truncated);
    assert!(!job.stderr_log_truncated);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn interrupted_status_preserves_unpublished_results_when_state_publication_fails() {
    let root = std::env::temp_dir().join(format!(
        "onec-agent-interrupted-state-failure-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let job_id = "job-interrupted-state-failure";
    let job_dir = root.join(job_id);
    fs::create_dir_all(&job_dir).expect("job dir");

    let running = AgentJobInfo {
        job_id: job_id.to_owned(),
        state: AgentJobState::Running,
        worker_pid: Some(i32::MAX as u32),
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: None,
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    write_state(&job_dir, 0, &running).expect("initial durable state");

    let workspace = crate::results::ResultWorkspace::prepare_job(
        &job_dir,
        job_id,
        &[onec_agent_protocol::ResultArtifactSpec::try_new(
            "report.bin".to_owned(),
            64,
            Some("application/octet-stream".to_owned()),
        )
        .expect("valid result declaration")],
    )
    .expect("prepare result workspace")
    .expect("non-empty workspace");
    let incoming = workspace.incoming_path().to_owned();
    fs::write(incoming.join("report.bin"), b"partial-result").expect("partial result");
    drop(workspace);

    // Force write_next_state() to fail without changing the latest durable sequence.
    // The state writer uses this exact process-scoped temporary pathname for sequence 1.
    let blocked_temp = job_dir.join(format!(".state-000001-{}.tmp", std::process::id()));
    fs::create_dir(&blocked_temp).expect("block next state temp file");

    let error = workflow::status(&root, job_id)
        .expect_err("failed Interrupted publication must fail status");
    assert!(
        error.kind() != io::ErrorKind::NotFound,
        "state publication failure should surface directly: {error}"
    );
    assert!(
        incoming.join("report.bin").is_file(),
        "unpublished result must survive uncertain Interrupted publication"
    );
    assert_eq!(
        read_latest_state(&job_dir)
            .expect("original durable state")
            .state,
        AgentJobState::Running,
        "cleanup authority must remain the last durable state"
    );

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn job_status_and_logs_expose_durable_storage_truncation() {
    let root = std::env::temp_dir().join(format!(
        "onec-agent-bounded-api-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let job_dir = root.join("job-test");
    ensure_private_directory(&root).expect("private job root");
    create_private_directory(&job_dir).expect("private job dir");
    let job = AgentJobInfo {
        job_id: "job-test".to_owned(),
        state: AgentJobState::Succeeded,
        worker_pid: None,
        spawn_owner_pid: None,
        process_pid: None,
        exit_code: Some(0),
        created_unix_ms: 1,
        started_unix_ms: Some(2),
        finished_unix_ms: Some(3),
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local: None,
    };
    write_state(&job_dir, 0, &job).expect("state");
    fs::write(job_dir.join("stdout.prev.log"), b"OLD").expect("previous stdout");
    fs::write(job_dir.join("stdout.log"), b"NEW").expect("active stdout");
    write_new_private_bytes(&job_dir.join("stdout.truncated"), b"truncated\n").expect("marker");

    let status = workflow::status(&root, "job-test").expect("job status");
    assert!(status.stdout_log_truncated);
    assert!(!status.stderr_log_truncated);

    let logs = workflow::logs(&root, "job-test", 64).expect("job logs");
    assert_eq!(logs.stdout, "OLDNEW");
    assert!(logs.stdout_truncated);
    assert!(logs.stdout_storage_truncated);
    assert!(!logs.stderr_truncated);
    assert!(!logs.stderr_storage_truncated);
    fs::remove_dir_all(root).expect("cleanup");
}
