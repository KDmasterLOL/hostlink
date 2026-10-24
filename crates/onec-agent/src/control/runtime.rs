//! Hello/status, structured exec, and persistent-job request handling.

use super::*;
use crate::environment::{AgentEnvironmentPolicy, RequestedChildKind};
use base64::Engine as _;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

const MAX_EXEC_OUTPUT_BYTES: usize = 256 * 1024;
const EXEC_SUPERVISION_INTERVAL: Duration = Duration::from_millis(25);
const EXEC_CONNECTION_PROBE_TIMEOUT: Duration = Duration::from_millis(1);
const AGENT_CAPABILITIES: &[&str] = &[
    "exec.env-v1",
    "exec.secret-env-v1",
    "exec.bounded-v1",
    "exec.raw-output-v1",
    "exec.stdin-v1",
    "exec.results-v1",
    "file-sha256-v1",
    "run-local-v1",
    "filesystem.scoped-remove-v1",
    "jobs-v1",
    "jobs.env-v1",
    "jobs.secret-env-v1",
    "jobs.stdin-v1",
    "jobs.results-v1",
    "jobs.local-candidate-v1",
    "native-attestation-v1",
    "native-invocation-observation-v1",
    "native-suite-policy-admission-v1",
    "results-v1",
];

fn agent_capabilities(native_suite_policy_pinned: bool) -> Vec<String> {
    AGENT_CAPABILITIES
        .iter()
        .copied()
        .filter(|capability| {
            *capability != "native-suite-policy-admission-v1" || native_suite_policy_pinned
        })
        .map(str::to_owned)
        .collect()
}

struct ImmediateExecRequest {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    environment: std::collections::BTreeMap<String, String>,
    secret_env: onec_agent_protocol::SecretEnvironment,
    stdin: Option<onec_agent_protocol::StdinPayload>,
    result_set_id: Option<String>,
    results: Vec<onec_agent_protocol::ResultArtifactSpec>,
    timeout_ms: u64,
    raw_output: bool,
}

#[derive(Debug)]
struct BoundedCapture {
    bytes: Vec<u8>,
    exceeded: Arc<AtomicBool>,
    cancellation: processkit::CancellationToken,
}

impl BoundedCapture {
    fn new(exceeded: Arc<AtomicBool>, cancellation: processkit::CancellationToken) -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_EXEC_OUTPUT_BYTES),
            exceeded,
            cancellation,
        }
    }
}

impl Write for BoundedCapture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = MAX_EXEC_OUTPUT_BYTES.saturating_sub(self.bytes.len());
        let keep = remaining.min(buffer.len());
        self.bytes.extend_from_slice(&buffer[..keep]);
        if keep < buffer.len() {
            self.exceeded.store(true, Ordering::Release);
            self.cancellation.cancel();
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct ImmediateExecCapture {
    state: Arc<Mutex<ImmediateExecCaptureState>>,
    exceeded: Arc<AtomicBool>,
}

struct ImmediateExecCaptureState {
    writer: Option<RedactingWriter<BoundedCapture>>,
    bytes: Option<Vec<u8>>,
}

impl ImmediateExecCapture {
    fn new(
        patterns: Vec<Vec<u8>>,
        cancellation: processkit::CancellationToken,
    ) -> io::Result<Self> {
        let exceeded = Arc::new(AtomicBool::new(false));
        let writer = RedactingWriter::new(
            BoundedCapture::new(Arc::clone(&exceeded), cancellation),
            patterns,
        )?;
        Ok(Self {
            state: Arc::new(Mutex::new(ImmediateExecCaptureState {
                writer: Some(writer),
                bytes: None,
            })),
            exceeded,
        })
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }

    fn write_chunk(&self, chunk: &[u8]) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("exec capture lock poisoned"))?;
        state
            .writer
            .as_mut()
            .ok_or_else(|| io::Error::other("exec capture was already finalized"))?
            .push(chunk)
    }

    fn finish(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("exec capture lock poisoned"))?;
        let writer = state
            .writer
            .take()
            .ok_or_else(|| io::Error::other("exec capture was already finalized"))?;
        state.bytes = Some(writer.finish()?.bytes);
        Ok(())
    }

    fn bytes(&self) -> io::Result<Vec<u8>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("exec capture lock poisoned"))?
            .bytes
            .clone()
            .ok_or_else(|| io::Error::other("exec capture did not finalize"))
    }
}

struct ProcesskitImmediateExecSink {
    capture: ImmediateExecCapture,
}

impl ProcesskitImmediateExecSink {
    fn new(capture: ImmediateExecCapture) -> Self {
        Self { capture }
    }
}

impl processkit::RawOutputSink for ProcesskitImmediateExecSink {
    fn write_chunk<'a>(&'a mut self, chunk: &'a [u8]) -> processkit::RawSinkFuture<'a> {
        Box::pin(async move { self.capture.write_chunk(chunk) })
    }

    fn finish(&mut self) -> processkit::RawSinkFuture<'_> {
        Box::pin(async move { self.capture.finish() })
    }
}

pub(super) fn handle(
    mut stream: TcpStream,
    runtime: &AgentRuntime,
    environment: &AgentEnvironmentPolicy,
    async_handle: &tokio::runtime::Handle,
    request: AgentRequestKind,
) -> io::Result<()> {
    match request {
        AgentRequestKind::Hello => {
            let agent_executable = env::current_exe()
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            let onec_executable = env::current_exe().ok().and_then(|path| {
                let candidate =
                    path.with_file_name(if cfg!(windows) { "onec.exe" } else { "onec" });
                candidate
                    .is_file()
                    .then(|| candidate.to_string_lossy().into_owned())
            });
            write_json_line(
                &mut stream,
                &AgentResponse::success(AgentResponseKind::Hello {
                    name: runtime.name.clone(),
                    agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                    hostname: system_hostname().unwrap_or_else(|_| "unknown".to_owned()),
                    os: env::consts::OS.to_owned(),
                    capabilities: agent_capabilities(runtime.native_suite_policy_sha256.is_some()),
                    agent_executable,
                    onec_executable,
                }),
            )
        }
        AgentRequestKind::Exec {
            program,
            args,
            cwd,
            env,
            secret_env,
            stdin,
            result_set_id,
            results,
            timeout_ms,
            raw_output,
        } => {
            let disconnect_probe = stream.try_clone()?;
            disconnect_probe.set_read_timeout(Some(EXEC_CONNECTION_PROBE_TIMEOUT))?;
            let response = async_handle.block_on(run_immediate_exec(
                &runtime.jobs_dir,
                environment,
                disconnect_probe,
                ImmediateExecRequest {
                    program,
                    args,
                    cwd,
                    environment: env,
                    secret_env,
                    stdin,
                    result_set_id,
                    results,
                    timeout_ms,
                    raw_output,
                },
            ));
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalPrepare {
            run_id,
            create_mapped_workspace,
        } => {
            let response =
                prepare_run_local_paths(&runtime.jobs_dir, &run_id, create_mapped_workspace);
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalStatus { run_id } => {
            let response = match jobs::status_by_run_id(&runtime.jobs_dir, &run_id) {
                Ok(job) => AgentResponse::success(AgentResponseKind::JobStatus { job }),
                Err(error) => {
                    AgentResponse::failure(format!("failed to resolve run-local job: {error}"))
                }
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::JobStart {
            program,
            args,
            cwd,
            env,
            secret_env,
            stdin,
            results,
            run_local,
        } => {
            let response = match jobs::start_job(
                &runtime.jobs_dir,
                environment,
                jobs::JobLaunchRequest {
                    program,
                    args,
                    cwd,
                    env,
                    stdin,
                    results,
                    run_local,
                    native_effect: None,
                    native_suite_policy_sha256: None,
                    native_suite_expected_tests: None,
                },
                secret_env,
            ) {
                Ok(job) => AgentResponse::success(AgentResponseKind::JobStarted { job }),
                Err(error) => AgentResponse::failure(format!("failed to start job: {error}")),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::NativeRunLocalJobStart {
            program,
            args,
            cwd,
            env,
            secret_env,
            stdin,
            results,
            run_local,
            native_effect,
            native_suite_policy,
        } => {
            let policy_digest = jobs::validate_native_suite_policy_admission(
                native_suite_policy.as_ref(),
                runtime.native_suite_policy_sha256.as_deref(),
                run_local.candidate_sha256(),
                &args,
                &env,
                native_effect,
            );
            let policy_digest = policy_digest.and_then(|digest| {
                if native_suite_policy.is_some() && (stdin.is_some() || !results.is_empty()) {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "native suite policy does not admit stdin or result artifacts",
                    ))
                } else {
                    Ok(digest)
                }
            });
            let response = match policy_digest {
                Ok(native_suite_policy_sha256) => match jobs::start_job(
                    &runtime.jobs_dir,
                    environment,
                    jobs::JobLaunchRequest {
                        program,
                        args,
                        cwd,
                        env,
                        stdin,
                        results,
                        run_local: Some(run_local),
                        native_effect: Some(native_effect),
                        native_suite_policy_sha256,
                        native_suite_expected_tests: native_suite_policy
                            .map(|policy| policy.expected_tests),
                    },
                    secret_env,
                ) {
                    Ok(job) => AgentResponse::success(AgentResponseKind::JobStarted { job }),
                    Err(error) => AgentResponse::failure(format!(
                        "failed to start native invocation job: {error}"
                    )),
                },
                Err(error) => AgentResponse::failure(format!(
                    "native suite policy admission rejected: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::JobStatus { job_id } => {
            let response = match jobs::status(&runtime.jobs_dir, &job_id) {
                Ok(job) => AgentResponse::success(AgentResponseKind::JobStatus { job }),
                Err(error) => {
                    AgentResponse::failure(format!("failed to read job {job_id}: {error}"))
                }
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::JobLogs { job_id, tail_bytes } => {
            let response = match jobs::logs(&runtime.jobs_dir, &job_id, tail_bytes) {
                Ok(logs) => AgentResponse::success(AgentResponseKind::JobLogs {
                    job_id,
                    stdout: logs.stdout,
                    stderr: logs.stderr,
                    stdout_truncated: logs.stdout_truncated,
                    stderr_truncated: logs.stderr_truncated,
                    stdout_storage_truncated: logs.stdout_storage_truncated,
                    stderr_storage_truncated: logs.stderr_storage_truncated,
                }),
                Err(error) => AgentResponse::failure(format!("failed to read job logs: {error}")),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::JobCancel { job_id } => {
            let response = match jobs::cancel(&runtime.jobs_dir, &job_id) {
                Ok(job) => AgentResponse::success(AgentResponseKind::JobCancelRequested { job }),
                Err(error) => {
                    AgentResponse::failure(format!("failed to cancel job {job_id}: {error}"))
                }
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalFinalize { job_id } => {
            let response = match finalize_run_local_job(&runtime.jobs_dir, &job_id) {
                Ok(removed) => AgentResponse::success(AgentResponseKind::PathRemoved { removed }),
                Err(error) => {
                    AgentResponse::failure(format!("failed to finalize run-local job: {error}"))
                }
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::NativeAttestationPublicKey => {
            let response = match crate::native_attestation::public_key(&runtime.jobs_dir) {
                Ok((signer_id, verifying_key_hex)) => {
                    AgentResponse::success(AgentResponseKind::NativeAttestationPublicKey {
                        signer_id,
                        verifying_key_hex,
                    })
                }
                Err(error) => AgentResponse::failure(format!(
                    "failed to load native attestation public key: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalAttest { job_id, challenge } => {
            let response = match crate::native_attestation::attest_run_local_success(
                &runtime.jobs_dir,
                &job_id,
                &challenge,
            ) {
                Ok((record, signature_hex)) => {
                    AgentResponse::success(AgentResponseKind::NativeExecutionAttestation {
                        record,
                        signature_hex,
                    })
                }
                Err(error) => AgentResponse::failure(format!(
                    "native execution attestation unavailable: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalAttestationFetch { job_id, challenge } => {
            let response = match crate::native_attestation::fetch_run_local_attestation(
                &runtime.jobs_dir,
                &job_id,
                &challenge,
            ) {
                Ok((record, signature_hex)) => {
                    AgentResponse::success(AgentResponseKind::NativeExecutionAttestationFetched {
                        record,
                        signature_hex,
                    })
                }
                Err(error) => AgentResponse::failure(format!(
                    "native execution attestation unavailable: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalInvocationObserve {
            job_id,
            challenge,
            invocation_sha256,
        } => {
            let response = match crate::native_attestation::observe_run_local_invocation(
                &runtime.jobs_dir,
                &job_id,
                &challenge,
                &invocation_sha256,
            ) {
                Ok((record, signature_hex)) => {
                    AgentResponse::success(AgentResponseKind::NativeInvocationObservation {
                        record,
                        signature_hex,
                    })
                }
                Err(error) => AgentResponse::failure(format!(
                    "native invocation observation unavailable: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalInvocationObservationFetch {
            job_id,
            challenge,
            invocation_sha256,
        } => {
            let response = match crate::native_attestation::fetch_run_local_invocation_observation(
                &runtime.jobs_dir,
                &job_id,
                &challenge,
                &invocation_sha256,
            ) {
                Ok((record, signature_hex)) => {
                    AgentResponse::success(AgentResponseKind::NativeInvocationObservationFetched {
                        record,
                        signature_hex,
                    })
                }
                Err(error) => AgentResponse::failure(format!(
                    "native invocation observation unavailable: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        AgentRequestKind::RunLocalAbandon { run_id } => {
            let response = match abandon_run_local_workspace(&runtime.jobs_dir, &run_id) {
                Ok(removed) => AgentResponse::success(AgentResponseKind::PathRemoved { removed }),
                Err(error) => AgentResponse::failure(format!(
                    "failed to abandon prepared run-local workspace: {error}"
                )),
            };
            write_json_line(&mut stream, &response)
        }
        _ => unreachable!("request routed to wrong control handler"),
    }
}

async fn run_immediate_exec(
    jobs_root: &Path,
    policy: &AgentEnvironmentPolicy,
    disconnect_probe: TcpStream,
    request: ImmediateExecRequest,
) -> AgentResponse {
    let ImmediateExecRequest {
        program,
        args,
        cwd,
        environment,
        secret_env,
        stdin,
        result_set_id,
        results,
        timeout_ms,
        raw_output,
    } = request;
    if timeout_ms == 0 || timeout_ms > onec_agent_protocol::MAX_EXEC_TIMEOUT_MS {
        return AgentResponse::failure_with_code(
            AgentErrorCode::ExecInvalidTimeout,
            format!(
                "exec timeout must be between 1 and {} ms, got {timeout_ms}",
                onec_agent_protocol::MAX_EXEC_TIMEOUT_MS
            ),
        );
    }

    let patterns = secret_env
        .values()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let cancellation = processkit::CancellationToken::new();
    let mut command = processkit::Command::new(&program)
        .args(&args)
        .create_no_window()
        .fail_on_stdin_broken_pipe()
        .cancel_on(cancellation.clone());
    command = match policy.prepare_processkit_command(
        command,
        &environment,
        &secret_env,
        RequestedChildKind::ImmediateExec,
    ) {
        Ok(command) => command,
        Err(error) => {
            return AgentResponse::failure(format!("exec environment is invalid: {error}"));
        }
    };
    command = with_immediate_exec_deadline(command, timeout_ms);

    let mut result_workspace = match crate::results::ResultWorkspace::prepare_exec(
        jobs_root,
        result_set_id.as_deref(),
        &results,
    ) {
        Ok(workspace) => workspace,
        Err(error) => {
            return AgentResponse::failure_with_code(
                AgentErrorCode::ExecResultInvalid,
                format!("exec result declaration is invalid: {error}"),
            );
        }
    };
    if let Some(workspace) = &result_workspace {
        command = command.env(hostlink_core::ONEC_RESULT_DIR_ENV, workspace.incoming_path());
    }
    if let Some(cwd) = cwd {
        command = command.current_dir(cwd);
    }
    command = match stdin {
        Some(stdin) => command.stdin(processkit::Stdin::from_bytes(stdin.as_bytes().to_vec())),
        None => command.stdin(processkit::Stdin::empty()),
    };

    let stdout_capture = match ImmediateExecCapture::new(patterns.clone(), cancellation.clone()) {
        Ok(capture) => capture,
        Err(error) => {
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecIoFailed,
                format!("failed to prepare stdout capture: {error}"),
            );
        }
    };
    let stderr_capture = match ImmediateExecCapture::new(patterns, cancellation.clone()) {
        Ok(capture) => capture,
        Err(error) => {
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecIoFailed,
                format!("failed to prepare stderr capture: {error}"),
            );
        }
    };
    let stdout_sink = stdout_capture.clone();
    command =
        command.stdout_raw_sink(move || ProcesskitImmediateExecSink::new(stdout_sink.clone()));
    let stderr_sink = stderr_capture.clone();
    command =
        command.stderr_raw_sink(move || ProcesskitImmediateExecSink::new(stderr_sink.clone()));

    let process_start_started = std::time::Instant::now();
    let mut child = match command.start().await {
        Ok(child) => child,
        Err(error) => {
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecStartFailed,
                format!("failed to start process: {error}"),
            );
        }
    };
    crate::agent_event(
        "exec.stage_completed",
        "info",
        crate::AgentEventFields::default()
            .stage("subprocess_start")
            .elapsed_ms(process_start_started.elapsed().as_millis() as u64),
    );

    let process_started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    let mut controller_disconnected = false;
    let mut disconnect_probe_error = None;
    let mut result_violation = None;
    let completion = loop {
        if timed_out
            || controller_disconnected
            || disconnect_probe_error.is_some()
            || result_violation.is_some()
            || stdout_capture.exceeded()
            || stderr_capture.exceeded()
        {
            break child.wait().await;
        }
        let probe = child.wait_for_tree_exit(EXEC_SUPERVISION_INTERVAL);
        let probe_result = tokio::select! {
            result = probe => result,
            () = tokio::time::sleep_until(deadline) => {
                timed_out = true;
                cancellation.cancel();
                continue;
            }
        };
        match probe_result {
            Ok(()) => break child.wait().await,
            Err(error) if matches!(error.reason(), processkit::ErrorReason::NotReady { .. }) => {
                match control_connection_closed(&disconnect_probe) {
                    Ok(true) => {
                        controller_disconnected = true;
                        cancellation.cancel();
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        disconnect_probe_error = Some(error);
                        cancellation.cancel();
                        continue;
                    }
                }
                if stdout_capture.exceeded() || stderr_capture.exceeded() {
                    continue;
                }
                if result_violation.is_none()
                    && let Some(workspace) = &result_workspace
                    && let Err(error) = workspace.supervise()
                {
                    result_violation = Some(error);
                    cancellation.cancel();
                }
            }
            Err(error) => {
                cancellation.cancel();
                let teardown = child.wait().await;
                if !processkit_teardown_confirmed(&teardown) {
                    let teardown_error =
                        discard_result_workspace_after_confirmed_processkit_teardown(
                            &mut result_workspace,
                            &teardown,
                        )
                        .expect_err("unconfirmed teardown must be reported");
                    return AgentResponse::failure_with_code(
                        AgentErrorCode::ExecIoFailed,
                        format!(
                            "failed while waiting for process tree: {error}; process-tree teardown was not confirmed: {teardown_error}"
                        ),
                    );
                }
                if let Err(cleanup) = discard_result_workspace_after_confirmed_processkit_teardown(
                    &mut result_workspace,
                    &teardown,
                ) {
                    return AgentResponse::failure_with_code(
                        AgentErrorCode::ExecIoFailed,
                        format!(
                            "failed while waiting for process tree: {error}; additionally failed to discard result workspace: {cleanup}"
                        ),
                    );
                }
                return AgentResponse::failure_with_code(
                    AgentErrorCode::ExecIoFailed,
                    format!("failed while waiting for process tree: {error}"),
                );
            }
        }
    };
    crate::agent_event(
        "exec.stage_completed",
        "info",
        crate::AgentEventFields::default()
            .stage("subprocess_lifetime")
            .elapsed_ms(process_started.elapsed().as_millis() as u64),
    );

    if let Err(error) = &completion
        && !processkit_teardown_confirmed(&completion)
    {
        return AgentResponse::failure_with_code(
            AgentErrorCode::ExecIoFailed,
            format!(
                "process-tree teardown was not confirmed: {error}; incoming result workspace retained"
            ),
        );
    }

    if stdout_capture.exceeded() || stderr_capture.exceeded() {
        return exec_failure_after_workspace_cleanup(
            &mut result_workspace,
            AgentErrorCode::ExecOutputLimit,
            format!(
                "process output exceeded {MAX_EXEC_OUTPUT_BYTES} bytes per stream after secret redaction"
            ),
        );
    }

    if timed_out {
        return exec_failure_after_workspace_cleanup(
            &mut result_workspace,
            AgentErrorCode::ExecTimeout,
            format!("process tree exceeded exec timeout of {timeout_ms} ms"),
        );
    }

    if controller_disconnected {
        return exec_failure_after_workspace_cleanup(
            &mut result_workspace,
            AgentErrorCode::ExecIoFailed,
            "controller connection closed during exec; process tree was terminated".into(),
        );
    }

    if let Some(error) = disconnect_probe_error {
        return exec_failure_after_workspace_cleanup(
            &mut result_workspace,
            AgentErrorCode::ExecIoFailed,
            format!("failed to supervise controller connection during exec: {error}"),
        );
    }

    if let Some(error) = result_violation {
        return exec_failure_after_workspace_cleanup(
            &mut result_workspace,
            AgentErrorCode::ExecResultInvalid,
            format!("result artifact policy violation: {error}"),
        );
    }

    let outcome = match completion {
        Ok(outcome) => outcome,
        Err(error) => {
            let message = if matches!(error.reason(), processkit::ErrorReason::Stdin { .. }) {
                format!("failed to write process stdin: {error}")
            } else {
                format!("failed while waiting for process tree: {error}")
            };
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecIoFailed,
                message,
            );
        }
    };

    let stdout = match stdout_capture.bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecIoFailed,
                format!("failed to finalize stdout capture: {error}"),
            );
        }
    };
    let stderr = match stderr_capture.bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return exec_failure_after_workspace_cleanup(
                &mut result_workspace,
                AgentErrorCode::ExecIoFailed,
                format!("failed to finalize stderr capture: {error}"),
            );
        }
    };

    let result_set = match &result_workspace {
        Some(workspace) => match workspace.finalize() {
            Ok(result_set) => Some(result_set),
            Err(error) => {
                return exec_failure_after_workspace_cleanup(
                    &mut result_workspace,
                    AgentErrorCode::ExecResultInvalid,
                    format!("failed to publish result artifacts: {error}"),
                );
            }
        },
        None => None,
    };

    let (stdout_text, stderr_text) = if raw_output {
        (String::new(), String::new())
    } else {
        (
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        )
    };
    AgentResponse::success(AgentResponseKind::Exec {
        exit_code: outcome.code(),
        stdout: stdout_text,
        stderr: stderr_text,
        stdout_base64: raw_output.then(|| base64::engine::general_purpose::STANDARD.encode(stdout)),
        stderr_base64: raw_output.then(|| base64::engine::general_purpose::STANDARD.encode(stderr)),
        result_set,
    })
}

fn control_connection_closed(stream: &TcpStream) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    match stream.peek(&mut byte) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

fn prepare_run_local_paths(
    jobs_root: &Path,
    run_id: &str,
    create_mapped_workspace: bool,
) -> AgentResponse {
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return AgentResponse::failure(
            "run-local identity must be a 32-character hexadecimal UUID",
        );
    }
    let cache_root = jobs_root.join("run-local-cache");
    let run_root_parent = jobs_root.join("run-local-runs");
    let run_root = run_root_parent.join(run_id);
    let _ownership = match jobs::lock_run_local_identity(jobs_root, run_id) {
        Ok(lock) => lock,
        Err(error) => {
            return AgentResponse::failure(format!("failed to own run-local identity: {error}"));
        }
    };
    if let Err(error) = jobs::ensure_run_local_not_abandoned(jobs_root, run_id) {
        return AgentResponse::failure(format!("run-local identity cannot be reused: {error}"));
    }
    match jobs::status_by_run_id_unlocked(jobs_root, run_id) {
        Ok(_) => {
            return AgentResponse::failure(
                "run-local identity already belongs to a durable job".to_owned(),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return AgentResponse::failure(format!(
                "failed to inspect run-local ownership: {error}"
            ));
        }
    }
    let result = (|| -> io::Result<()> {
        if create_mapped_workspace {
            validate_run_local_directory(jobs_root)?;
            ensure_run_local_private_directory(&cache_root)?;
            ensure_run_local_private_directory(&run_root_parent)?;
            hostlink_core::create_private_directory(&run_root)?;
            hostlink_core::create_private_directory(&run_root.join("mapped"))?;
        } else {
            fs::create_dir_all(&cache_root)?;
            fs::create_dir_all(&run_root_parent)?;
            fs::create_dir(&run_root)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => AgentResponse::success(AgentResponseKind::RunLocalPaths {
            cache_root: cache_root.to_string_lossy().into_owned(),
            run_root_parent: run_root_parent.to_string_lossy().into_owned(),
            run_root: run_root.to_string_lossy().into_owned(),
        }),
        Err(error) => AgentResponse::failure(format!("failed to prepare run-local paths: {error}")),
    }
}

fn validate_run_local_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || crate::results::std_metadata_is_symlink_or_reparse(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local ownership root is not a regular directory",
        ));
    }
    Ok(())
}

fn ensure_run_local_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !crate::results::std_metadata_is_symlink_or_reparse(&metadata) =>
        {
            hostlink_core::restrict_private_directory(path).map_err(io::Error::other)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local cache/workspace parent must be an owned regular directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            hostlink_core::create_private_directory(path)
        }
        Err(error) => Err(error),
    }
}

fn finalize_run_local_job(jobs_root: &Path, job_id: &str) -> io::Result<bool> {
    let job = jobs::status(jobs_root, job_id)?;
    if !job.state.is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local job is not terminal",
        ));
    }
    if job.state == onec_agent_protocol::AgentJobState::Interrupted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interrupted job process-tree teardown is unconfirmed; preserve its workspace",
        ));
    }
    let identity = job.run_local.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "job has no run-local ownership metadata",
        )
    })?;
    let _ownership = jobs::lock_run_local_identity(jobs_root, identity.run_id())?;
    let job = jobs::status(jobs_root, job_id)?;
    if job.run_local.as_ref().map(|current| current.run_id()) != Some(identity.run_id())
        || !job.state.is_terminal()
        || job.state == onec_agent_protocol::AgentJobState::Interrupted
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local job ownership changed before finalization",
        ));
    }
    if job.result_set.is_some() && !crate::results::job_result_set_cleaned(jobs_root, &job.job_id)?
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "declared results must be retrieved and cleaned before workspace finalization",
        ));
    }
    let parent = jobs_root.join("run-local-runs");
    let workspace = parent.join(identity.run_id());
    hostlink_core::remove_path_scoped(&parent, &workspace, true, true)
}

fn abandon_run_local_workspace(jobs_root: &Path, run_id: &str) -> io::Result<bool> {
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid run-local identity",
        ));
    }
    let _ownership = jobs::lock_run_local_identity(jobs_root, run_id)?;
    match jobs::status_by_run_id_unlocked(jobs_root, run_id) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a durable job owns this run-local workspace",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    jobs::mark_run_local_abandoned(jobs_root, run_id)?;
    let parent = jobs_root.join("run-local-runs");
    hostlink_core::remove_path_scoped(&parent, &parent.join(run_id), true, true)
}

fn discard_result_workspace_with(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    discard: impl FnOnce(crate::results::ResultWorkspace) -> io::Result<bool>,
) -> io::Result<()> {
    if let Some(workspace) = workspace.take() {
        discard(workspace)?;
    }
    Ok(())
}

fn exec_failure_after_workspace_cleanup(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    code: AgentErrorCode,
    primary: String,
) -> AgentResponse {
    exec_failure_after_workspace_cleanup_with(
        workspace,
        code,
        primary,
        crate::results::ResultWorkspace::discard,
    )
}

fn exec_failure_after_workspace_cleanup_with(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    code: AgentErrorCode,
    primary: String,
    discard: impl FnOnce(crate::results::ResultWorkspace) -> io::Result<bool>,
) -> AgentResponse {
    let message = match discard_result_workspace_with(workspace, discard) {
        Ok(()) => primary,
        Err(cleanup) => {
            format!("{primary}; additionally failed to discard result workspace: {cleanup}")
        }
    };
    AgentResponse::failure_with_code(code, message)
}

fn discard_result_workspace_after_confirmed_processkit_teardown(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    teardown: &processkit::Result<processkit::Outcome>,
) -> io::Result<()> {
    if !processkit_teardown_confirmed(teardown) {
        let detail = teardown
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_else(|| "process tree teardown was not confirmed".to_owned());
        return Err(io::Error::other(detail));
    }
    if let Some(workspace) = workspace.take() {
        workspace.discard()?;
    }
    Ok(())
}

fn processkit_teardown_confirmed(teardown: &processkit::Result<processkit::Outcome>) -> bool {
    match teardown {
        Ok(_) => true,
        // ProcessKit reports Stdin/RawSink only after drive_to_exit, output pumps,
        // and the teardown-error checkpoint; a generic Io/Teardown error does not
        // establish the same guarantee.
        Err(error) => {
            error.is_cancelled()
                || matches!(
                    error.reason(),
                    processkit::ErrorReason::Stdin { .. } | processkit::ErrorReason::RawSink { .. }
                )
        }
    }
}

fn immediate_exec_deadline_unix_ms(timeout_ms: u64) -> u64 {
    hostlink_core::unix_time_ms().saturating_add(timeout_ms)
}

fn with_immediate_exec_deadline(
    command: processkit::Command,
    timeout_ms: u64,
) -> processkit::Command {
    command.env(
        hostlink_core::ONEC_EXEC_DEADLINE_UNIX_MS_ENV,
        immediate_exec_deadline_unix_ms(timeout_ms).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use onec_agent_protocol::ResultArtifactSpec;

    #[test]
    fn capabilities_do_not_promote_process_observation_to_suite_evidence() {
        let unconfigured = agent_capabilities(false);
        let pinned = agent_capabilities(true);
        for capabilities in [&unconfigured, &pinned] {
            assert!(
                capabilities
                    .iter()
                    .any(|capability| capability == "native-invocation-observation-v1")
            );
            assert!(
                !capabilities
                    .iter()
                    .any(|capability| capability == "native-suite-result-v1")
            );
        }
        assert!(
            !unconfigured
                .iter()
                .any(|capability| capability == "native-suite-policy-admission-v1"),
            "an Agent without an independently provisioned policy pin must fail before staging"
        );
        assert!(
            pinned
                .iter()
                .any(|capability| capability == "native-suite-policy-admission-v1"),
            "an independently pinned Agent can advertise policy admission"
        );
    }

    #[test]
    fn immediate_exec_deadline_covers_the_requested_agent_timeout() {
        let timeout_ms = 60_000;
        let before = hostlink_core::unix_time_ms();
        let deadline = immediate_exec_deadline_unix_ms(timeout_ms);
        let after = hostlink_core::unix_time_ms();

        assert!(deadline >= before + timeout_ms);
        assert!(deadline <= after + timeout_ms);
    }

    #[tokio::test]
    async fn immediate_exec_child_receives_the_agent_owned_deadline() {
        let timeout_ms = 60_000;
        #[cfg(unix)]
        let command = processkit::Command::new("sh")
            .args(["-c", "printf %s \"$ONEC_EXEC_DEADLINE_UNIX_MS\""]);
        #[cfg(windows)]
        let command = processkit::Command::new("powershell.exe").args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::Out.Write($env:ONEC_EXEC_DEADLINE_UNIX_MS)",
        ]);
        let command = with_immediate_exec_deadline(command, timeout_ms);
        let running = processkit::JobRunner
            .start(&command)
            .await
            .expect("spawn deadline probe");
        let output = running.output_bytes().await.expect("deadline probe output");
        let deadline = std::str::from_utf8(output.stdout())
            .expect("UTF-8 deadline")
            .parse::<u64>()
            .expect("agent-owned deadline value");
        let now = hostlink_core::unix_time_ms();

        assert!(deadline >= now);
        assert!(deadline <= now + timeout_ms + 1_000);
    }

    #[test]
    fn run_local_paths_are_agent_owned_and_run_identity_scoped() {
        let root = tempfile::tempdir().expect("root");
        let jobs = root.path().join("jobs");
        std::fs::create_dir(&jobs).expect("jobs root");
        hostlink_core::ensure_private_directory(&jobs).expect("private jobs root");
        let run_id = "0123456789abcdef0123456789abcdef";

        let response = prepare_run_local_paths(&jobs, run_id, false);
        let Some(AgentResponseKind::RunLocalPaths {
            cache_root,
            run_root_parent,
            run_root,
        }) = response.response
        else {
            panic!("expected run-local paths: {response:?}");
        };
        assert_eq!(
            std::path::Path::new(&cache_root),
            jobs.join("run-local-cache")
        );
        assert_eq!(
            std::path::Path::new(&run_root_parent),
            jobs.join("run-local-runs")
        );
        assert_eq!(
            std::path::Path::new(&run_root),
            jobs.join("run-local-runs").join(run_id)
        );
        assert!(std::path::Path::new(&cache_root).is_dir());
        assert!(std::path::Path::new(&run_root).is_dir());

        let duplicate = prepare_run_local_paths(&jobs, run_id, false);
        assert!(!duplicate.ok, "run identity must not be reusable");
        let invalid = prepare_run_local_paths(&jobs, "../escape", false);
        assert!(
            !invalid.ok,
            "invalid identity must fail before path creation"
        );
        let mapped_id = "1123456789abcdef0123456789abcdef";
        let mapped = prepare_run_local_paths(&jobs, mapped_id, true);
        let Some(AgentResponseKind::RunLocalPaths { run_root, .. }) = mapped.response else {
            panic!("expected mapped workspace: {mapped:?}");
        };
        assert!(Path::new(&run_root).join("mapped").is_dir());
        assert!(
            abandon_run_local_workspace(&jobs, mapped_id).expect("abandon unstarted workspace")
        );
        assert!(!Path::new(&run_root).exists());
        assert!(
            !prepare_run_local_paths(&jobs, mapped_id, true).ok,
            "abandoned run identity must not be reusable after reservation release"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_run_local_prepare_rejects_linked_cache_and_workspace_roots_before_upload() {
        use std::os::unix::fs::symlink;

        for linked_name in ["run-local-cache", "run-local-runs"] {
            let root = tempfile::tempdir().expect("root");
            let jobs = root.path().join("jobs");
            std::fs::create_dir(&jobs).expect("jobs root");
            hostlink_core::ensure_private_directory(&jobs).expect("private jobs root");
            let outside = root.path().join("outside");
            std::fs::create_dir(&outside).expect("outside directory");
            symlink(&outside, jobs.join(linked_name)).expect("linked agent-owned root");

            let response = prepare_run_local_paths(&jobs, "0123456789abcdef0123456789abcdef", true);
            assert!(!response.ok, "linked {linked_name} must fail preparation");
            assert_eq!(
                std::fs::read_dir(&outside)
                    .expect("outside remains inspectable")
                    .count(),
                0,
                "preparation must not stage content through {linked_name}"
            );
            assert!(
                response.response.is_none(),
                "failed preparation must not return remote upload paths"
            );
        }
    }

    #[test]
    fn run_local_abandon_waits_for_jobstart_ownership_publication() {
        let root = tempfile::tempdir().expect("root");
        let jobs = root.path().join("jobs");
        fs::create_dir(&jobs).expect("jobs root");
        hostlink_core::ensure_private_directory(&jobs).expect("private jobs root");
        let run_id = "2123456789abcdef0123456789abcdef";
        let job_id = "job-run-local-ownership-race";
        let response = prepare_run_local_paths(&jobs, run_id, true);
        assert!(response.ok, "prepare workspace: {response:?}");
        let workspace = jobs.join("run-local-runs").join(run_id);
        let ownership = jobs::lock_run_local_identity(&jobs, run_id).expect("start ownership lock");

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let jobs_for_abandon = jobs.clone();
        let run_for_abandon = run_id.to_owned();
        let abandon = std::thread::spawn(move || {
            started_tx.send(()).expect("started signal");
            let result = abandon_run_local_workspace(&jobs_for_abandon, &run_for_abandon);
            finished_tx.send(()).expect("finished signal");
            result
        });
        started_rx.recv().expect("abandon thread started");
        assert!(
            matches!(
                finished_rx.recv_timeout(std::time::Duration::from_millis(30)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "abandon must wait while JobStart owns the run identity"
        );
        assert!(workspace.is_dir(), "workspace must remain during JobStart");

        let job_dir = jobs.join(job_id);
        fs::create_dir(&job_dir).expect("job directory");
        hostlink_core::ensure_private_directory(&job_dir).expect("private job directory");
        let job = onec_agent_protocol::AgentJobInfo {
            job_id: job_id.to_owned(),
            state: onec_agent_protocol::AgentJobState::Queued,
            worker_pid: None,
            spawn_owner_pid: Some(std::process::id()),
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
                    run_id.to_owned(),
                    format!("sha256-{}.exe", "a".repeat(64)),
                    "a".repeat(64),
                    Vec::new(),
                )
                .expect("valid run-local identity"),
            ),
        };
        fs::write(
            job_dir.join("state-000000.json"),
            serde_json::to_vec(&serde_json::json!({"version": 1, "job": job})).expect("state JSON"),
        )
        .expect("persist JobStart ownership");
        drop(ownership);

        assert_eq!(
            abandon
                .join()
                .expect("abandon thread")
                .expect_err("job owns workspace")
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(
            workspace.is_dir(),
            "abandon must not remove JobStart workspace"
        );
    }

    #[test]
    fn run_local_finalization_requires_confirmed_terminal_state_and_cleaned_results() {
        let root = tempfile::tempdir().expect("root");
        let jobs = root.path().join("jobs");
        std::fs::create_dir(&jobs).expect("jobs root");
        let run_id = "0123456789abcdef0123456789abcdef";
        let job_id = "job-run-local-finalize";
        let run_parent = jobs.join("run-local-runs");
        let workspace = run_parent.join(run_id);
        std::fs::create_dir_all(workspace.join("mapped")).expect("owned workspace");
        hostlink_core::ensure_private_directory(&run_parent).expect("private run parent");
        hostlink_core::ensure_private_directory(&workspace).expect("private run workspace");
        hostlink_core::ensure_private_directory(&workspace.join("mapped"))
            .expect("private mapped workspace");
        let job_dir = jobs.join(job_id);
        std::fs::create_dir(&job_dir).expect("job directory");
        hostlink_core::ensure_private_directory(&job_dir).expect("private job directory");

        let mut job = onec_agent_protocol::AgentJobInfo {
            job_id: job_id.to_owned(),
            state: onec_agent_protocol::AgentJobState::Running,
            worker_pid: None,
            spawn_owner_pid: None,
            process_pid: None,
            exit_code: None,
            created_unix_ms: 1,
            started_unix_ms: Some(1),
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
        let save = |job: &onec_agent_protocol::AgentJobInfo| {
            std::fs::write(
                job_dir.join("state-000000.json"),
                serde_json::to_vec(&serde_json::json!({"version": 1, "job": job}))
                    .expect("state JSON"),
            )
            .expect("persist job state");
        };
        save(&job);
        assert!(finalize_run_local_job(&jobs, job_id).is_err());
        assert!(workspace.is_dir());

        job.state = onec_agent_protocol::AgentJobState::Interrupted;
        job.finished_unix_ms = Some(2);
        save(&job);
        assert!(finalize_run_local_job(&jobs, job_id).is_err());
        assert!(workspace.is_dir());

        job.state = onec_agent_protocol::AgentJobState::Succeeded;
        job.result_set = Some(
            onec_agent_protocol::ResultSetInfo::try_new(
                onec_agent_protocol::ResultOwner::job(job_id).expect("valid job owner"),
                Vec::new(),
            )
            .expect("valid empty result set"),
        );
        save(&job);
        std::fs::create_dir(job_dir.join("results")).expect("published result directory");
        assert!(finalize_run_local_job(&jobs, job_id).is_err());
        std::fs::remove_dir(job_dir.join("results")).expect("simulate successful result cleanup");
        assert!(finalize_run_local_job(&jobs, job_id).expect("safe finalization"));
        assert!(!workspace.exists());
    }

    #[test]
    fn immediate_exec_output_limit_is_applied_after_redaction() {
        let token = processkit::CancellationToken::new();
        let capture =
            ImmediateExecCapture::new(vec![b"x".to_vec()], token.clone()).expect("capture");
        let raw = vec![b'x'; (MAX_EXEC_OUTPUT_BYTES / b"[REDACTED]".len()) + 1];

        capture.write_chunk(&raw).expect("write raw output");
        capture.finish().expect("finalize redaction");

        assert!(
            raw.len() < MAX_EXEC_OUTPUT_BYTES,
            "raw bytes alone must stay below the response ceiling"
        );
        assert!(
            capture.exceeded(),
            "redacted expansion must hit the ceiling"
        );
        assert!(token.is_cancelled(), "overflow must stop the process tree");
        assert_eq!(
            capture.bytes().expect("bounded bytes").len(),
            MAX_EXEC_OUTPUT_BYTES
        );
    }

    #[tokio::test]
    async fn unconfirmed_policy_termination_preserves_incoming_workspace() {
        let root = tempfile::tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let mut workspace = Some(
            crate::results::ResultWorkspace::prepare_exec(
                &jobs,
                Some("result-termination-unknown"),
                &[
                    ResultArtifactSpec::try_new("report.bin".to_owned(), 64, None)
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
        std::fs::write(incoming.join("report.bin"), b"evidence").expect("write evidence");

        let teardown = processkit::Command::new("definitely-missing-onec-agent-test-command")
            .start()
            .await
            .expect_err("missing command must fail before a process tree is owned");
        let error = discard_result_workspace_after_confirmed_processkit_teardown(
            &mut workspace,
            &Err(teardown),
        )
        .expect_err("unconfirmed teardown must preserve evidence");

        assert!(!error.to_string().is_empty());
        assert!(incoming.join("report.bin").is_file());
        workspace
            .expect("workspace remains owned")
            .discard()
            .expect("test cleanup");
    }

    #[test]
    fn exec_primary_and_workspace_cleanup_failures_are_reported_and_workspace_is_retained() {
        let root = tempfile::tempdir().expect("root");
        let jobs = root.path().join("jobs");
        let mut workspace = Some(
            crate::results::ResultWorkspace::prepare_exec(
                &jobs,
                Some("result-cleanup-failure"),
                &[
                    ResultArtifactSpec::try_new("report.bin".to_owned(), 64, None)
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
        std::fs::write(incoming.join("report.bin"), b"retained evidence").expect("write evidence");

        let response = exec_failure_after_workspace_cleanup_with(
            &mut workspace,
            AgentErrorCode::ExecIoFailed,
            "primary capture failure".to_owned(),
            |_workspace| Err(io::Error::other("injected scoped cleanup failure")),
        );

        assert_eq!(
            response.error.as_deref(),
            Some(
                "primary capture failure; additionally failed to discard result workspace: injected scoped cleanup failure"
            )
        );
        assert!(incoming.join("report.bin").is_file());
        assert!(
            workspace.is_none(),
            "failed discard relinquishes the handle"
        );
    }
}
