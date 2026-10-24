use onec_agent_protocol::{
    AgentJobState, AgentRequest, AgentRequestKind, AgentResponse, AgentResponseKind,
    ONEC_AGENT_JOB_SYSTEM, ResultArtifactSpec, ResultOwner, SecretEnvironment, read_json_line,
    write_json_line,
};
#[cfg(unix)]
use onec_agent_protocol::{MAX_STDIN_PAYLOAD_BYTES, StdinPayload};
use onec_core::{ONEC_JOB_ID_ENV, ONEC_JOB_SYSTEM_ENV, ONEC_PARENT_RUN_ID_ENV};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SECRET: &str = "0123456789abcdef";
static REAL_AGENT_TEST_LOCK: Mutex<()> = Mutex::new(());

fn temp_dir() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "onec-agent-persistent-jobs-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

fn request(port: u16, kind: AgentRequestKind) -> AgentResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write_json_line(&mut stream, &AgentRequest::new(SECRET, kind)).expect("request");
    read_json_line(BufReader::new(stream)).expect("response")
}

fn agent_binary() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("ONEC_AGENT_TEST_BINARY") {
        return std::path::PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(current) = std::env::current_exe()
            && let Some(parent) = current.parent()
        {
            let sibling = parent.join("onec-agent.exe");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_onec-agent"))
}

fn start_agent(root: &Path, port: u16) -> Child {
    let secret = root.join("secret.txt");
    fs::write(&secret, format!("{SECRET}\n")).expect("secret");
    let config = root.join("agent.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "name": "jobs-test",
            "listen": format!("127.0.0.1:{port}"),
            "secret_env": "",
            "secret_file": secret,
            "jobs_dir": root.join("jobs")
        }))
        .expect("config json"),
    )
    .expect("config");
    spawn_agent(&config, port, &[])
}

fn start_agent_with_environment_secret(
    root: &Path,
    port: u16,
    secret_env_name: &str,
    inherited_environment: &[(&str, &str)],
) -> Child {
    let config = root.join("agent-env.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "name": "environment-test",
            "listen": format!("127.0.0.1:{port}"),
            "secret_env": secret_env_name,
            "jobs_dir": root.join("jobs")
        }))
        .expect("config json"),
    )
    .expect("config");
    let mut environment = inherited_environment.to_vec();
    environment.push((secret_env_name, SECRET));
    spawn_agent(&config, port, &environment)
}

fn spawn_agent(config: &Path, port: u16, inherited_environment: &[(&str, &str)]) -> Child {
    let mut command = Command::new(agent_binary());
    command
        .args(["serve", "--config"])
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (name, value) in inherited_environment {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("agent");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        assert!(
            child.try_wait().expect("agent state").is_none(),
            "agent exited"
        );
        assert!(Instant::now() < deadline, "agent did not listen");
        thread::sleep(Duration::from_millis(50));
    }
}

fn successful_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        (
            "sh".into(),
            vec!["-c".into(), "printf job-out; printf job-err >&2".into()],
        )
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec![
                "/d".into(),
                "/c".into(),
                "echo|set /p=job-out & echo|set /p=job-err 1>&2 & exit /b 0".into(),
            ],
        )
    }
}

fn long_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        ("sh".into(), vec!["-c".into(), "sleep 30".into()])
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec!["/d".into(), "/c".into(), "ping 127.0.0.1 -n 31 >nul".into()],
        )
    }
}

fn delayed_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        (
            "sh".into(),
            vec!["-c".into(), "sleep 1; printf survived-restart".into()],
        )
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec![
                "/d".into(),
                "/c".into(),
                "ping 127.0.0.1 -n 2 >nul & echo|set /p=survived-restart & exit /b 0".into(),
            ],
        )
    }
}

fn result_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        (
            "sh".into(),
            vec![
                "-c".into(),
                "printf durable-result > \"$ONEC_RESULT_DIR/report.bin\"".into(),
            ],
        )
    }
    #[cfg(windows)]
    {
        let current = std::env::current_exe().expect("current test executable");
        (
            current.to_string_lossy().into_owned(),
            vec![
                "regression_inv_130_windows_result_writer_fixture".into(),
                "--exact".into(),
                "--ignored".into(),
                "--test-threads=1".into(),
            ],
        )
    }
}

#[cfg(windows)]
#[test]
#[ignore = "test-only durable result writer invoked by the Windows integration fixture"]
fn regression_inv_130_windows_result_writer_fixture() {
    let result_dir = std::env::var_os(onec_core::ONEC_RESULT_DIR_ENV)
        .expect("agent must inject ONEC_RESULT_DIR");
    fs::write(
        std::path::PathBuf::from(result_dir).join("report.bin"),
        b"durable-result",
    )
    .expect("write durable result fixture");
}

fn download_result(
    port: u16,
    owner: ResultOwner,
    name: &str,
) -> (onec_agent_protocol::ResultArtifactInfo, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect result");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            SECRET,
            AgentRequestKind::ResultDownload {
                owner,
                name: name.to_owned(),
            },
        ),
    )
    .expect("result request");
    let mut reader = BufReader::new(stream);
    let response: AgentResponse = read_json_line(&mut reader).expect("result header");
    let Some(AgentResponseKind::ResultDownloadReady { artifact }) = response.response else {
        panic!("unexpected result header: {response:?}");
    };
    let mut bytes = vec![0_u8; usize::try_from(artifact.bytes()).expect("bounded result size")];
    reader.read_exact(&mut bytes).expect("result bytes");
    (artifact, bytes)
}

fn secret_echo_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        (
            "sh".into(),
            vec![
                "-c".into(),
                "test -n \"$INV069_SECRET\" && printf '%s' \"$INV069_SECRET\" && printf '%s' \"$INV069_SECRET\" >&2"
                    .into(),
            ],
        )
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec![
                "/d".into(),
                "/c".into(),
                "if defined INV069_SECRET (<nul set /p =%INV069_SECRET% & <nul set /p =%INV069_SECRET% 1>&2 & exit /b 0) else exit /b 1"
                    .into(),
            ],
        )
    }
}

fn environment_dump_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        ("env".into(), Vec::new())
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec!["/d".into(), "/c".into(), "set".into()],
        )
    }
}

fn environment_value<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (actual, value) = line.split_once('=')?;
        let matches = if cfg!(windows) {
            actual.eq_ignore_ascii_case(name)
        } else {
            actual == name
        };
        matches.then_some(value)
    })
}

fn correlation_echo_command() -> (String, Vec<String>) {
    #[cfg(unix)]
    {
        (
            "sh".into(),
            vec![
                "-c".into(),
                format!(
                    "printf 'parent=%s\nsystem=%s\nid=%s\n' \"${}\" \"${}\" \"${}\"",
                    ONEC_PARENT_RUN_ID_ENV, ONEC_JOB_SYSTEM_ENV, ONEC_JOB_ID_ENV
                ),
            ],
        )
    }
    #[cfg(windows)]
    {
        (
            "cmd.exe".into(),
            vec![
                "/d".into(),
                "/c".into(),
                format!(
                    "echo parent=%{}%&echo system=%{}%&echo id=%{}%",
                    ONEC_PARENT_RUN_ID_ENV, ONEC_JOB_SYSTEM_ENV, ONEC_JOB_ID_ENV
                ),
            ],
        )
    }
}

fn assert_tree_does_not_contain(root: &Path, needle: &[u8]) {
    if !root.exists() {
        return;
    }
    for entry in fs::read_dir(root).expect("read tree") {
        let entry = entry.expect("tree entry");
        let path = entry.path();
        if path.is_dir() {
            assert_tree_does_not_contain(&path, needle);
        } else {
            let bytes = fs::read(&path).expect("read tree file");
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "secret bytes persisted in {}",
                path.display()
            );
        }
    }
}

fn wait_for_state(port: u16, job_id: &str, expected: AgentJobState) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = request(
            port,
            AgentRequestKind::JobStatus {
                job_id: job_id.into(),
            },
        );
        let Some(AgentResponseKind::JobStatus { job }) = response.response else {
            panic!("unexpected status response: {response:?}");
        };
        if job.state == expected {
            return;
        }
        assert!(
            !job.state.is_terminal(),
            "job reached unexpected terminal state: {job:?}"
        );
        assert!(Instant::now() < deadline, "job did not reach {expected:?}");
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn agent_exec_and_jobs_use_sanitized_environment_contract() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    const CONTROL_ENV: &str = "CUSTOM_AGENT_CONTROL_SECRET";
    const CHILD_SECRET: &str = "explicit-child-secret";

    let mut agent = start_agent_with_environment_secret(
        &root,
        port,
        CONTROL_ENV,
        &[
            ("ONEC_RESIDENT_SENTINEL", "ambient-onec"),
            ("RESIDENT_NORMAL_SENTINEL", "ambient-normal"),
            ("GITHUB_TOKEN", "ambient-token"),
        ],
    );

    let mut ordinary = BTreeMap::new();
    ordinary.insert("ONEC_LABEL".to_owned(), "explicit-onec".to_owned());
    ordinary.insert("REQUEST_NORMAL".to_owned(), "explicit-normal".to_owned());
    let mut secrets = BTreeMap::new();
    secrets.insert(CONTROL_ENV.to_owned(), CHILD_SECRET.to_owned());

    let (program, args) = environment_dump_command();
    let exec = request(
        port,
        AgentRequestKind::Exec {
            program,
            args,
            cwd: None,
            env: ordinary.clone(),
            secret_env: SecretEnvironment::new(secrets.clone()),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 10_000,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec { stdout, .. }) = exec.response else {
        panic!("unexpected exec response: {exec:?}");
    };
    assert!(environment_value(&stdout, "PATH").is_some(), "{stdout}");
    assert_eq!(
        environment_value(&stdout, "ONEC_LABEL"),
        Some("explicit-onec")
    );
    assert_eq!(
        environment_value(&stdout, "REQUEST_NORMAL"),
        Some("explicit-normal")
    );
    assert_eq!(environment_value(&stdout, CONTROL_ENV), Some("[REDACTED]"));
    assert!(environment_value(&stdout, "ONEC_RESIDENT_SENTINEL").is_none());
    assert!(environment_value(&stdout, "RESIDENT_NORMAL_SENTINEL").is_none());
    assert!(environment_value(&stdout, "GITHUB_TOKEN").is_none());
    assert!(!stdout.contains(SECRET));
    assert!(!stdout.contains(CHILD_SECRET));

    ordinary.insert(ONEC_JOB_SYSTEM_ENV.to_owned(), "mcp_job".to_owned());
    ordinary.insert(ONEC_JOB_ID_ENV.to_owned(), "spoofed-id".to_owned());
    let (program, args) = environment_dump_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: ordinary,
            secret_env: SecretEnvironment::new(secrets),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected job start response: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job_id.clone(),
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected job logs: {logs:?}");
    };
    assert!(environment_value(&stdout, "PATH").is_some(), "{stdout}");
    assert_eq!(
        environment_value(&stdout, "ONEC_LABEL"),
        Some("explicit-onec")
    );
    assert_eq!(
        environment_value(&stdout, "REQUEST_NORMAL"),
        Some("explicit-normal")
    );
    assert_eq!(environment_value(&stdout, CONTROL_ENV), Some("[REDACTED]"));
    assert_eq!(
        environment_value(&stdout, ONEC_JOB_SYSTEM_ENV),
        Some(ONEC_AGENT_JOB_SYSTEM)
    );
    assert_eq!(
        environment_value(&stdout, ONEC_JOB_ID_ENV),
        Some(job_id.as_str())
    );
    assert!(environment_value(&stdout, "ONEC_RESIDENT_SENTINEL").is_none());
    assert!(environment_value(&stdout, "RESIDENT_NORMAL_SENTINEL").is_none());
    assert!(environment_value(&stdout, "GITHUB_TOKEN").is_none());
    assert!(!stdout.contains("spoofed-id"));
    assert!(!stdout.contains(SECRET));
    assert!(!stdout.contains(CHILD_SECRET));

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn persistent_job_injects_agent_owned_correlation_identity() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let (program, args) = correlation_echo_command();
    let mut environment = BTreeMap::new();
    environment.insert(
        ONEC_PARENT_RUN_ID_ENV.to_owned(),
        "parent-run-42".to_owned(),
    );
    environment.insert(ONEC_JOB_SYSTEM_ENV.to_owned(), "mcp_job".to_owned());
    environment.insert(ONEC_JOB_ID_ENV.to_owned(), "spoofed-id".to_owned());
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: environment,
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job_id.clone(),
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected logs response: {logs:?}");
    };
    assert!(
        stdout.lines().any(|line| line == "parent=parent-run-42"),
        "{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line == format!("system={ONEC_AGENT_JOB_SYSTEM}")),
        "{stdout}"
    );
    assert!(
        stdout.lines().any(|line| line == format!("id={job_id}")),
        "{stdout}"
    );
    assert!(!stdout.contains("spoofed-id"), "{stdout}");
    assert!(!stdout.contains("system=mcp_job"), "{stdout}");

    agent.kill().ok();
    agent.wait().ok();
    fs::remove_dir_all(root).ok();
}

#[test]
fn persistent_job_runs_logs_and_cancels_through_real_agent_binary() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let hello = request(port, AgentRequestKind::Hello);
    let Some(AgentResponseKind::Hello { capabilities, .. }) = hello.response else {
        panic!("unexpected hello: {hello:?}");
    };
    assert!(capabilities.iter().any(|value| value == "jobs-v1"));

    let (program, args) = successful_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let completed_id = job.job_id;
    wait_for_state(port, &completed_id, AgentJobState::Succeeded);

    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: completed_id.clone(),
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, stderr, .. }) = logs.response else {
        panic!("unexpected logs response: {logs:?}");
    };
    assert!(stdout.contains("job-out"));
    assert!(stderr.contains("job-err"));

    let (program, args) = long_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let canceled_id = job.job_id;
    wait_for_state(port, &canceled_id, AgentJobState::Running);
    let canceled = request(
        port,
        AgentRequestKind::JobCancel {
            job_id: canceled_id.clone(),
        },
    );
    assert!(matches!(
        canceled.response,
        Some(AgentResponseKind::JobCancelRequested { .. })
    ));
    wait_for_state(port, &canceled_id, AgentJobState::Canceled);

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn durable_local_candidate_reconnects_retrieves_results_and_cleans_owned_workspace() {
    use sha2::{Digest as _, Sha256};

    let _serial = REAL_AGENT_TEST_LOCK
        .lock()
        .expect("serialize real Agent lifecycle");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);
    let hello = request(port, AgentRequestKind::Hello);
    let Some(AgentResponseKind::Hello { capabilities, .. }) = hello.response else {
        panic!("unexpected hello: {hello:?}");
    };
    assert!(
        capabilities
            .iter()
            .any(|capability| capability == "jobs.local-candidate-v1")
    );

    let run_id = "0123456789abcdef0123456789abcdef";
    let prepared = request(
        port,
        AgentRequestKind::RunLocalPrepare {
            run_id: run_id.to_owned(),
            create_mapped_workspace: true,
        },
    );
    let Some(AgentResponseKind::RunLocalPaths {
        cache_root,
        run_root,
        ..
    }) = prepared.response
    else {
        panic!("unexpected prepare response: {prepared:?}");
    };
    let candidate_bytes = fs::read("/bin/sh").expect("read local shell executable");
    let candidate_sha256 = format!("{:x}", Sha256::digest(&candidate_bytes));
    let candidate_name = format!("sha256-{candidate_sha256}.sh");
    let candidate_path = std::path::PathBuf::from(cache_root).join(&candidate_name);
    fs::write(&candidate_path, &candidate_bytes).expect("stage exact candidate");
    let mapped_bytes = b"mapped-data";
    let mapped_sha256 = format!("{:x}", Sha256::digest(mapped_bytes));
    let mapped_path = std::path::PathBuf::from(&run_root)
        .join("mapped")
        .join(format!("ONEC_INPUT-sha256-{mapped_sha256}"));
    fs::write(&mapped_path, mapped_bytes).expect("stage mapped input in job workspace");
    let started = request(port, AgentRequestKind::JobStart {
        program: candidate_path.to_string_lossy().into_owned(),
        args: vec!["-c".to_owned(), "test -f \"$ONEC_INPUT\" && printf lifecycle-log && printf result-data > \"$ONEC_RESULT_DIR/report.bin\"".to_owned()],
        cwd: Some(run_root.clone()),
        env: BTreeMap::from([("ONEC_INPUT".to_owned(), mapped_path.to_string_lossy().into_owned())]),
        secret_env: SecretEnvironment::default(),
        stdin: None,
        results: vec![ResultArtifactSpec::try_new("report.bin".to_owned(), 1024, None)
            .expect("valid result declaration")],
        run_local: Some(onec_agent_protocol::RunLocalJobIdentity::try_new(
            run_id.to_owned(),
            candidate_name.clone(),
            candidate_sha256.clone(),
            vec![onec_agent_protocol::RunLocalMappedFile::try_new(
                "ONEC_INPUT".to_owned(),
                mapped_sha256,
            )
            .expect("valid mapped identity")],
        )
        .expect("valid run-local identity")),
    });
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected local candidate start response: {started:?}");
    };
    let job_id = job.job_id;

    // Controller/Agent control loss is observational; the detached worker owns its process tree.
    agent.kill().expect("disconnect Agent control process");
    let _ = agent.wait().expect("reap disconnected Agent");
    let mut reconnected = start_agent(&root, port);
    let deadline = Instant::now() + Duration::from_secs(10);
    let job = loop {
        let response = request(
            port,
            AgentRequestKind::RunLocalStatus {
                run_id: run_id.to_owned(),
            },
        );
        let Some(AgentResponseKind::JobStatus { job }) = response.response else {
            panic!("run identity did not reconnect: {response:?}");
        };
        if job.state == AgentJobState::Succeeded {
            break job;
        }
        assert!(
            !job.state.is_terminal(),
            "unexpected terminal state after reconnect: {job:?}"
        );
        assert!(
            Instant::now() < deadline,
            "durable local candidate did not finish"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        job.run_local.as_ref().map(|identity| identity.run_id()),
        Some(run_id)
    );
    assert!(
        job.result_set.is_some(),
        "terminal state retains result ownership metadata"
    );
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job_id.clone(),
            tail_bytes: 4096,
        },
    );
    assert!(
        matches!(logs.response, Some(AgentResponseKind::JobLogs { stdout, .. }) if stdout.contains("lifecycle-log"))
    );
    let (artifact, bytes) = download_result(
        port,
        ResultOwner::job(job_id.clone()).expect("valid job owner"),
        "report.bin",
    );
    assert_eq!(artifact.sha256(), format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(bytes, b"result-data");
    let cleaned_results = request(
        port,
        AgentRequestKind::ResultCleanup {
            owner: ResultOwner::job(job_id.clone()).expect("valid job owner"),
        },
    );
    assert!(matches!(
        cleaned_results.response,
        Some(AgentResponseKind::ResultCleaned { .. })
    ));
    let finalized = request(
        port,
        AgentRequestKind::RunLocalFinalize {
            job_id: job_id.clone(),
        },
    );
    assert!(matches!(
        finalized.response,
        Some(AgentResponseKind::PathRemoved { removed: true })
    ));
    assert!(!std::path::Path::new(&run_root).exists());
    assert!(
        candidate_path.is_file(),
        "immutable executable cache survives run cleanup"
    );

    // A second durable candidate request is explicitly canceled and finalized by its typed owner.
    let cancel_run_id = "1123456789abcdef0123456789abcdef";
    let prepared = request(
        port,
        AgentRequestKind::RunLocalPrepare {
            run_id: cancel_run_id.to_owned(),
            create_mapped_workspace: true,
        },
    );
    let Some(AgentResponseKind::RunLocalPaths {
        run_root: cancel_root,
        ..
    }) = prepared.response
    else {
        panic!("prepare cancellation run: {prepared:?}");
    };
    let canceled = request(
        port,
        AgentRequestKind::JobStart {
            program: candidate_path.to_string_lossy().into_owned(),
            args: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: Some(cancel_root),
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: Vec::new(),
            run_local: Some(
                onec_agent_protocol::RunLocalJobIdentity::try_new(
                    cancel_run_id.to_owned(),
                    candidate_name,
                    candidate_sha256,
                    Vec::new(),
                )
                .expect("valid run-local identity"),
            ),
        },
    );
    let Some(AgentResponseKind::JobStarted { job: canceled_job }) = canceled.response else {
        panic!("start cancelable job: {canceled:?}");
    };
    wait_for_state(port, &canceled_job.job_id, AgentJobState::Running);
    request(
        port,
        AgentRequestKind::JobCancel {
            job_id: canceled_job.job_id.clone(),
        },
    );
    wait_for_state(port, &canceled_job.job_id, AgentJobState::Canceled);
    assert!(matches!(
        request(
            port,
            AgentRequestKind::RunLocalFinalize {
                job_id: canceled_job.job_id
            }
        )
        .response,
        Some(AgentResponseKind::PathRemoved { removed: true })
    ));

    reconnected.kill().expect("stop reconnected Agent");
    let _ = reconnected.wait();
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn persistent_job_delivers_multiline_stdin_and_removes_launch_request() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);
    let payload = b"durable line one\ndurable line two\n".to_vec();

    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "cat".into(),
            args: Vec::new(),
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: Some(StdinPayload::try_new(payload.clone()).expect("bounded stdin")),
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected stdin job start response: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Succeeded);

    let request_file = root.join("jobs").join(&job.job_id).join("request.json");
    assert!(
        !request_file.exists(),
        "durable launch request must be removed before/while child execution"
    );
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job.job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, stderr, .. }) = logs.response else {
        panic!("unexpected stdin job logs response: {logs:?}");
    };
    assert_eq!(stdout.as_bytes(), payload);
    assert!(stderr.is_empty(), "{stderr}");

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn persistent_job_cancel_remains_authoritative_with_blocked_stdin_writer() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);
    let payload =
        StdinPayload::try_new(vec![b'x'; MAX_STDIN_PAYLOAD_BYTES]).expect("max bounded stdin");

    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "sh".into(),
            args: vec!["-c".into(), "sleep 30".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: Some(payload),
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected blocked-stdin job response: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Running);
    let cancel_started = Instant::now();
    let canceled = request(
        port,
        AgentRequestKind::JobCancel {
            job_id: job.job_id.clone(),
        },
    );
    assert!(matches!(
        canceled.response,
        Some(AgentResponseKind::JobCancelRequested { .. })
    ));
    wait_for_state(port, &job.job_id, AgentJobState::Canceled);
    assert!(
        cancel_started.elapsed() < Duration::from_secs(5),
        "blocked stdin writer delayed cancellation: {:?}",
        cancel_started.elapsed()
    );

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn persistent_job_cancel_terminates_descendant_tree_via_shared_owner() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let marker = root.join("descendant-survived.txt");
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let mut environment = BTreeMap::new();
    environment.insert(
        "ONEC_JOB_TREE_MARKER".to_owned(),
        marker.to_string_lossy().into_owned(),
    );
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                "sh -c 'sleep 2; printf survived > \"$ONEC_JOB_TREE_MARKER\"' & sleep 30".into(),
            ],
            cwd: None,
            env: environment,
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Running);

    let canceled = request(
        port,
        AgentRequestKind::JobCancel {
            job_id: job_id.clone(),
        },
    );
    assert!(matches!(
        canceled.response,
        Some(AgentResponseKind::JobCancelRequested { .. })
    ));
    wait_for_state(port, &job_id, AgentJobState::Canceled);
    thread::sleep(Duration::from_millis(2500));
    assert!(
        !marker.exists(),
        "job cancellation must terminate descendants before they can write the marker"
    );

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(windows)]
#[test]
fn persistent_job_cancel_terminates_windows_descendant_tree_via_shared_owner() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let child_started = root.join("child-started.txt");
    let marker = root.join("descendant-survived.txt");
    fs::write(
        root.join("child.cmd"),
        "@echo off\r\necho started>child-started.txt\r\nping 127.0.0.1 -n 6 >nul\r\necho survived>descendant-survived.txt\r\n",
    )
    .expect("child script");
    fs::write(
        root.join("parent.cmd"),
        "@echo off\r\nstart \"\" /b cmd.exe /d /c child.cmd\r\nping 127.0.0.1 -n 31 >nul\r\n",
    )
    .expect("parent script");

    let port = free_port();
    let mut agent = start_agent(&root, port);
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "cmd.exe".into(),
            args: vec!["/d".into(), "/c".into(), "parent.cmd".into()],
            cwd: Some(root.to_string_lossy().into_owned()),
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Running);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !child_started.exists() {
        assert!(Instant::now() < deadline, "descendant did not start");
        thread::sleep(Duration::from_millis(50));
    }

    let canceled = request(
        port,
        AgentRequestKind::JobCancel {
            job_id: job_id.clone(),
        },
    );
    assert!(matches!(
        canceled.response,
        Some(AgentResponseKind::JobCancelRequested { .. })
    ));
    wait_for_state(port, &job_id, AgentJobState::Canceled);
    thread::sleep(Duration::from_secs(6));
    assert!(
        !marker.exists(),
        "Windows durable-job cancellation must terminate a started descendant tree"
    );

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn persistent_jobs_preserve_unicode_argv_cwd_and_environment_without_shell_transport() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let cwd = root.join("Каталог (job) & 100%");
    fs::create_dir_all(&cwd).expect("unicode cwd");
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let hello = request(port, AgentRequestKind::Hello);
    let Some(AgentResponseKind::Hello { capabilities, .. }) = hello.response else {
        panic!("unexpected hello: {hello:?}");
    };
    assert!(capabilities.iter().any(|value| value == "jobs.env-v1"));

    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "printf".into(),
            args: vec!["%s".into(), "Проверка Обмена".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected argv job: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job.job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected argv logs: {logs:?}");
    };
    assert_eq!(stdout, "Проверка Обмена");

    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "pwd".into(),
            args: Vec::new(),
            cwd: Some(cwd.to_string_lossy().into_owned()),
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected cwd job: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job.job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected cwd logs: {logs:?}");
    };
    assert_eq!(stdout.trim_end(), cwd.to_string_lossy());

    let mut environment = BTreeMap::new();
    environment.insert("ONEC_LABEL".to_owned(), "Набор Юникод".to_owned());
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program: "env".into(),
            args: Vec::new(),
            cwd: None,
            env: environment,
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected env job: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job.job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected env logs: {logs:?}");
    };
    assert!(stdout.lines().any(|line| line == "ONEC_LABEL=Набор Юникод"));

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn persistent_job_result_survives_status_and_typed_download() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let (program, args) = result_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: vec![
                ResultArtifactSpec::try_new(
                    "report.bin".into(),
                    1024,
                    Some("application/octet-stream".into()),
                )
                .expect("valid result declaration"),
            ],
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected result job start: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Succeeded);
    let status = request(
        port,
        AgentRequestKind::JobStatus {
            job_id: job_id.clone(),
        },
    );
    let Some(AgentResponseKind::JobStatus { job }) = status.response else {
        panic!("unexpected result job status: {status:?}");
    };
    let result_set = job.result_set.expect("published result set");
    assert_eq!(result_set.owner().job_id(), Some(job_id.as_str()));
    assert_eq!(result_set.artifacts().len(), 1);

    let owner = ResultOwner::job(job_id.clone()).expect("valid job owner");
    let (artifact, bytes) = download_result(port, owner.clone(), "report.bin");
    assert_eq!(bytes, b"durable-result");
    assert_eq!(artifact, result_set.artifacts()[0]);

    let cleanup = request(port, AgentRequestKind::ResultCleanup { owner });
    assert!(matches!(
        cleanup.response,
        Some(AgentResponseKind::ResultCleaned { removed: true })
    ));
    let status = request(port, AgentRequestKind::JobStatus { job_id });
    assert!(
        status.ok,
        "result cleanup must not remove durable job state"
    );

    agent.kill().expect("stop agent");
    let _ = agent.wait();
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn regression_inv_069_persistent_job_secret_environment_is_not_persisted() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let sentinel = format!(
        "INV069_SECRET_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut secrets = BTreeMap::new();
    secrets.insert("INV069_SECRET".to_owned(), sentinel.clone());
    let (program, args) = secret_echo_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: SecretEnvironment::new(secrets),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected secret job response: {started:?}");
    };
    wait_for_state(port, &job.job_id, AgentJobState::Succeeded);

    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id: job.job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, stderr, .. }) = logs.response else {
        panic!("unexpected secret logs response: {logs:?}");
    };
    agent.kill().expect("stop agent");
    let _ = agent.wait();

    assert_eq!(stdout.trim_end(), "[REDACTED]");
    assert_eq!(stderr.trim_end(), "[REDACTED]");
    assert!(!stdout.contains(&sentinel));
    assert!(!stderr.contains(&sentinel));
    assert_tree_does_not_contain(&root.join("jobs"), sentinel.as_bytes());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn persistent_job_survives_agent_restart_and_remains_queryable() {
    let _guard = REAL_AGENT_TEST_LOCK.lock().expect("real agent test lock");
    let root = temp_dir();
    let port = free_port();
    let mut agent = start_agent(&root, port);

    let (program, args) = delayed_command();
    let started = request(
        port,
        AgentRequestKind::JobStart {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            results: Vec::new(),
            run_local: None,
        },
    );
    let Some(AgentResponseKind::JobStarted { job }) = started.response else {
        panic!("unexpected start response: {started:?}");
    };
    let job_id = job.job_id;
    wait_for_state(port, &job_id, AgentJobState::Running);

    agent.kill().expect("stop serving agent");
    let _ = agent.wait();
    thread::sleep(Duration::from_millis(1400));

    let mut restarted = start_agent(&root, port);
    wait_for_state(port, &job_id, AgentJobState::Succeeded);
    let logs = request(
        port,
        AgentRequestKind::JobLogs {
            job_id,
            tail_bytes: 64 * 1024,
        },
    );
    let Some(AgentResponseKind::JobLogs { stdout, .. }) = logs.response else {
        panic!("unexpected logs response: {logs:?}");
    };
    assert!(stdout.contains("survived-restart"));

    restarted.kill().expect("stop restarted agent");
    let _ = restarted.wait();
    fs::remove_dir_all(root).expect("cleanup");
}
