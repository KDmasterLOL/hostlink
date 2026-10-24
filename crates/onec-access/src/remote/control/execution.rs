//! Shell-free process execution and persistent-job RPC.

use crate::AppResult;
use crate::remote::model::RemoteAgentClient;
use bon::bon;
use hostlink_protocol::{
    AgentRequestKind, AgentResponseKind, DEFAULT_EXEC_TIMEOUT_MS, NativeExecutionEffect,
    NativeSuitePolicy, ResultArtifactSpec, RunLocalJobIdentity, SecretEnvironment, StdinPayload,
    validate_result_specs,
};
use std::collections::BTreeMap;
use uuid::Uuid;

struct ExecRequest {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    secret_env: SecretEnvironment,
    stdin: Option<StdinPayload>,
    results: Vec<ResultArtifactSpec>,
    timeout_ms: u64,
    raw_output: bool,
}

struct JobStartRequest {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    secret_env: SecretEnvironment,
    stdin: Option<StdinPayload>,
    results: Vec<ResultArtifactSpec>,
    run_local: Option<RunLocalJobIdentity>,
}

struct NativeJobStartRequest {
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    stdin: Option<StdinPayload>,
    results: Vec<ResultArtifactSpec>,
    run_local: RunLocalJobIdentity,
    native_effect: NativeExecutionEffect,
    native_suite_policy: Option<NativeSuitePolicy>,
}

#[bon]
impl RemoteAgentClient {
    /// Verifies that the selected Agent supports source-exact durable local-candidate jobs.
    pub async fn require_local_candidate_job_support(&self) -> AppResult<()> {
        self.require_capability("jobs.local-candidate-v1").await
    }

    /// Executes one bounded remote process with the authenticated agent's account privileges.
    ///
    /// Passing argv avoids controller-side shell interpolation, but this is trusted arbitrary
    /// process execution, not a sandbox: the program may invoke an interpreter or script. Toolkit
    /// cleanup must use the typed owned-root-scoped filesystem operation instead.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when capability negotiation, transport, or remote execution
    /// fails.
    #[builder(
        start_fn(name = exec, vis = "pub"),
        builder_type(vis = "pub")
    )]
    async fn exec_impl(
        &self,
        #[builder(start_fn, into)] program: String,
        #[builder(default)] args: Vec<String>,
        cwd: Option<String>,
        #[builder(default = DEFAULT_EXEC_TIMEOUT_MS)] timeout_ms: u64,
        #[builder(default)] raw_output: bool,
        #[builder(default)] env: BTreeMap<String, String>,
        #[builder(default)] secret_env: SecretEnvironment,
        stdin: Option<StdinPayload>,
        #[builder(default)] results: Vec<ResultArtifactSpec>,
    ) -> AppResult<AgentResponseKind> {
        self.exec_request(ExecRequest {
            program,
            args,
            cwd,
            env,
            secret_env,
            stdin,
            results,
            timeout_ms,
            raw_output,
        })
        .await
    }

    async fn exec_request(&self, request: ExecRequest) -> AppResult<AgentResponseKind> {
        validate_result_specs(&request.results).map_err(crate::invalid_config)?;
        let mut required_capabilities = Vec::with_capacity(4);
        if !request.secret_env.is_empty() {
            required_capabilities.push("exec.secret-env-v1");
        }
        if !request.env.is_empty() {
            required_capabilities.push("exec.env-v1");
        }
        if request.stdin.is_some() {
            required_capabilities.push("exec.stdin-v1");
        }
        if request.raw_output {
            required_capabilities.push("exec.raw-output-v1");
        }
        let result_set_id = exec_result_set_id(&request.results);
        if result_set_id.is_some() {
            required_capabilities.push("exec.results-v1");
            required_capabilities.push("results-v1");
        }
        required_capabilities.push("exec.bounded-v1");
        self.require_capabilities(&required_capabilities).await?;
        let response = self
            .request_owned_exec(exec_request_kind(request, result_set_id.clone()))
            .await?;
        validate_exec_result_owner(&response, result_set_id.as_deref())?;
        Ok(response)
    }

    /// Starts one durable remote job with the authenticated agent's account privileges.
    ///
    /// JobStart is trusted arbitrary process execution, not a sandbox. Toolkit cleanup must use
    /// the typed owned-root-scoped filesystem operation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when capability negotiation, transport, or job creation fails.
    #[builder(
        start_fn(name = start_job, vis = "pub"),
        builder_type(vis = "pub")
    )]
    async fn start_job_impl(
        &self,
        #[builder(start_fn, into)] program: String,
        #[builder(default)] args: Vec<String>,
        cwd: Option<String>,
        #[builder(default)] env: BTreeMap<String, String>,
        #[builder(default)] secret_env: SecretEnvironment,
        stdin: Option<StdinPayload>,
        #[builder(default)] results: Vec<ResultArtifactSpec>,
        run_local: Option<RunLocalJobIdentity>,
    ) -> AppResult<AgentResponseKind> {
        self.job_start_request(JobStartRequest {
            program,
            args,
            cwd,
            env,
            secret_env,
            stdin,
            results,
            run_local,
        })
        .await
    }

    async fn job_start_request(&self, request: JobStartRequest) -> AppResult<AgentResponseKind> {
        validate_result_specs(&request.results).map_err(crate::invalid_config)?;
        let mut required_capabilities = Vec::with_capacity(4);
        if !request.secret_env.is_empty() {
            required_capabilities.push("jobs.secret-env-v1");
        }
        if !request.env.is_empty() {
            required_capabilities.push("jobs.env-v1");
        }
        if request.stdin.is_some() {
            required_capabilities.push("jobs.stdin-v1");
        }
        if !request.results.is_empty() {
            required_capabilities.push("jobs.results-v1");
            required_capabilities.push("results-v1");
        }
        if request.run_local.is_some() {
            required_capabilities.push("jobs.local-candidate-v1");
        }
        required_capabilities.push("jobs-v1");
        self.require_capabilities(&required_capabilities).await?;
        self.request(job_start_request_kind(request)).await
    }

    /// Starts one durable run-local job using the Agent's signed invocation commitment path.
    ///
    /// When `native_suite_policy` is supplied, its runner SHA, argv, environment, and effect must
    /// match this launch exactly. The policy is sent to the Agent, which checks its independent
    /// administrator-configured digest pin; the controller never retries without the policy.
    /// Secret environment is deliberately unavailable because Agent-native invocation identity
    /// commits only ordinary environment values.
    ///
    /// # Errors
    ///
    /// Returns an error when required Agent capabilities are absent, policy fields do not match
    /// the launch, the Agent rejects policy admission, or the RPC fails.
    #[builder(
        start_fn(name = start_native_run_local_job, vis = "pub"),
        builder_type(vis = "pub")
    )]
    async fn start_native_run_local_job_impl(
        &self,
        #[builder(start_fn, into)] program: String,
        #[builder(default)] args: Vec<String>,
        cwd: Option<String>,
        #[builder(default)] env: BTreeMap<String, String>,
        stdin: Option<StdinPayload>,
        #[builder(default)] results: Vec<ResultArtifactSpec>,
        run_local: RunLocalJobIdentity,
        native_effect: NativeExecutionEffect,
        native_suite_policy: Option<NativeSuitePolicy>,
    ) -> AppResult<AgentResponseKind> {
        self.native_job_start_request(NativeJobStartRequest {
            program,
            args,
            cwd,
            env,
            stdin,
            results,
            run_local,
            native_effect,
            native_suite_policy,
        })
        .await
    }

    async fn native_job_start_request(
        &self,
        request: NativeJobStartRequest,
    ) -> AppResult<AgentResponseKind> {
        validate_result_specs(&request.results).map_err(crate::invalid_config)?;
        if let Some(policy) = &request.native_suite_policy {
            policy.sha256().map_err(|error| {
                crate::invalid_config(format!("invalid native suite policy: {error}"))
            })?;
            if policy.runner_sha256 != request.run_local.candidate_sha256()
                || policy.args != request.args
                || policy.env != request.env
                || policy.effect != request.native_effect
                || request.stdin.is_some()
                || !request.results.is_empty()
            {
                return Err(crate::invalid_config(
                    "native suite policy does not match the exact candidate launch fields"
                        .to_owned(),
                ));
            }
        }
        let mut required_capabilities = vec![
            "jobs.local-candidate-v1",
            "native-invocation-observation-v1",
            "jobs-v1",
        ];
        if request.native_suite_policy.is_some() {
            required_capabilities.push("native-suite-policy-admission-v1");
        }
        if !request.env.is_empty() {
            required_capabilities.push("jobs.env-v1");
        }
        if request.stdin.is_some() {
            required_capabilities.push("jobs.stdin-v1");
        }
        if !request.results.is_empty() {
            required_capabilities.push("jobs.results-v1");
            required_capabilities.push("results-v1");
        }
        self.require_capabilities(&required_capabilities).await?;
        self.request(AgentRequestKind::NativeRunLocalJobStart {
            program: request.program,
            args: request.args,
            cwd: request.cwd,
            env: request.env,
            secret_env: SecretEnvironment::default(),
            stdin: request.stdin,
            results: request.results,
            run_local: request.run_local,
            native_effect: request.native_effect,
            native_suite_policy: request.native_suite_policy,
        })
        .await
    }

    /// Reads durable metadata for one remote job.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when `jobs-v1` is unavailable or the request fails.
    pub async fn job_status(&self, job_id: impl Into<String>) -> AppResult<AgentResponseKind> {
        self.request_job_observation(AgentRequestKind::JobStatus {
            job_id: job_id.into(),
        })
        .await
    }

    /// Reads bounded durable stdout/stderr tails for one remote job.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when `jobs-v1` is unavailable or the request fails.
    pub async fn job_logs(
        &self,
        job_id: impl Into<String>,
        tail_bytes: u64,
    ) -> AppResult<AgentResponseKind> {
        self.request_job_observation(AgentRequestKind::JobLogs {
            job_id: job_id.into(),
            tail_bytes,
        })
        .await
    }

    /// Requests cancellation of one durable remote job.
    ///
    /// # Errors
    ///
    /// Returns [`crate::AppError`] when `jobs-v1` is unavailable or the request fails.
    pub async fn job_cancel(&self, job_id: impl Into<String>) -> AppResult<AgentResponseKind> {
        self.require_capability("jobs-v1").await?;
        self.request(AgentRequestKind::JobCancel {
            job_id: job_id.into(),
        })
        .await
    }

    /// Removes the Agent-owned workspace of one terminal run-local job.
    pub async fn finalize_run_local_job(
        &self,
        job_id: impl Into<String>,
    ) -> AppResult<AgentResponseKind> {
        self.require_capability("jobs.local-candidate-v1").await?;
        self.request(AgentRequestKind::RunLocalFinalize {
            job_id: job_id.into(),
        })
        .await
    }

    /// Requests the one-shot Agent signature for a completed exact invocation.
    pub async fn observe_run_local_invocation(
        &self,
        job_id: impl Into<String>,
        challenge: impl Into<String>,
        invocation_sha256: impl Into<String>,
    ) -> AppResult<AgentResponseKind> {
        self.require_capability("native-invocation-observation-v1")
            .await?;
        self.request(AgentRequestKind::RunLocalInvocationObserve {
            job_id: job_id.into(),
            challenge: challenge.into(),
            invocation_sha256: invocation_sha256.into(),
        })
        .await
    }

    /// Fetches an existing Agent invocation signature without signing or retrying.
    pub async fn fetch_run_local_invocation_observation(
        &self,
        job_id: impl Into<String>,
        challenge: impl Into<String>,
        invocation_sha256: impl Into<String>,
    ) -> AppResult<AgentResponseKind> {
        self.require_capability("native-invocation-observation-v1")
            .await?;
        self.request(AgentRequestKind::RunLocalInvocationObservationFetch {
            job_id: job_id.into(),
            challenge: challenge.into(),
            invocation_sha256: invocation_sha256.into(),
        })
        .await
    }
}

fn exec_result_set_id(results: &[ResultArtifactSpec]) -> Option<String> {
    (!results.is_empty()).then(|| Uuid::new_v4().simple().to_string())
}

fn validate_exec_result_owner(
    response: &AgentResponseKind,
    expected_id: Option<&str>,
) -> AppResult<()> {
    let Some(expected_id) = expected_id else {
        return Ok(());
    };
    let AgentResponseKind::Exec {
        result_set: Some(result_set),
        ..
    } = response
    else {
        return Err(crate::invalid_config(
            "remote exec omitted declared result metadata".to_owned(),
        ));
    };
    if result_set.owner().exec_id() != Some(expected_id) {
        return Err(crate::invalid_config(
            "remote exec result metadata belongs to a different request".to_owned(),
        ));
    }
    Ok(())
}

fn exec_request_kind(request: ExecRequest, result_set_id: Option<String>) -> AgentRequestKind {
    AgentRequestKind::Exec {
        program: request.program,
        args: request.args,
        cwd: request.cwd,
        env: request.env,
        secret_env: request.secret_env,
        stdin: request.stdin,
        result_set_id,
        results: request.results,
        timeout_ms: request.timeout_ms,
        raw_output: request.raw_output,
    }
}

fn job_start_request_kind(request: JobStartRequest) -> AgentRequestKind {
    AgentRequestKind::JobStart {
        program: request.program,
        args: request.args,
        cwd: request.cwd,
        env: request.env,
        secret_env: request.secret_env,
        stdin: request.stdin,
        results: request.results,
        run_local: request.run_local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hostlink_protocol::AgentRequest;

    fn result_spec() -> ResultArtifactSpec {
        ResultArtifactSpec::try_new("report.bin".to_owned(), 1024, None)
            .expect("valid result declaration")
    }

    #[test]
    fn exec_result_request_has_unique_opaque_owner_and_legacy_fields_stay_omitted() {
        let specs = vec![result_spec()];
        let first_id = exec_result_set_id(&specs).expect("result ID");
        let second_id = exec_result_set_id(&specs).expect("second result ID");
        assert_ne!(first_id, second_id);
        hostlink_protocol::validate_result_set_id(&first_id).expect("valid opaque ID");

        let request = exec_request_kind(
            ExecRequest {
                program: "worker".to_owned(),
                args: Vec::new(),
                cwd: None,
                env: BTreeMap::new(),
                secret_env: SecretEnvironment::default(),
                stdin: None,
                results: specs,
                timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
                raw_output: false,
            },
            Some(first_id.clone()),
        );
        let wire = serde_json::to_value(AgentRequest::new("secret", request)).expect("JSON");
        assert_eq!(wire["request"]["result_set_id"], first_id);
        assert_eq!(wire["request"]["results"][0]["name"], "report.bin");
        assert_eq!(wire["request"]["results"][0]["max_bytes"], 1024);

        let legacy = exec_request_kind(
            ExecRequest {
                program: "worker".to_owned(),
                args: Vec::new(),
                cwd: None,
                env: BTreeMap::new(),
                secret_env: SecretEnvironment::default(),
                stdin: None,
                results: Vec::new(),
                timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
                raw_output: false,
            },
            None,
        );
        let legacy = serde_json::to_value(AgentRequest::new("secret", legacy)).expect("JSON");
        assert_eq!(legacy["request"]["timeout_ms"], DEFAULT_EXEC_TIMEOUT_MS);
        assert_eq!(legacy["request"]["args"], serde_json::json!([]));
        assert!(legacy["request"].get("cwd").is_none());
        assert!(legacy["request"].get("env").is_none());
        assert!(legacy["request"].get("secret_env").is_none());
        assert!(legacy["request"].get("stdin").is_none());
        assert!(legacy["request"].get("result_set_id").is_none());
        assert!(legacy["request"].get("results").is_none());
    }

    #[test]
    fn job_start_request_carries_declared_results() {
        let request = job_start_request_kind(JobStartRequest {
            program: "worker".to_owned(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            secret_env: SecretEnvironment::default(),
            stdin: None,
            results: vec![result_spec()],
            run_local: None,
        });
        let wire = serde_json::to_value(AgentRequest::new("secret", request)).expect("JSON");
        assert_eq!(wire["request"]["results"][0]["name"], "report.bin");
        assert_eq!(wire["request"]["results"][0]["max_bytes"], 1024);
        assert_eq!(wire["request"]["args"], serde_json::json!([]));
        assert!(wire["request"].get("cwd").is_none());
        assert!(wire["request"].get("env").is_none());
        assert!(wire["request"].get("secret_env").is_none());
        assert!(wire["request"].get("stdin").is_none());
        assert!(wire["request"].get("timeout_ms").is_none());
    }

    #[test]
    fn exec_and_durable_job_wire_preserve_argv_cwd_and_environment() {
        let args = vec![
            String::new(),
            "two words".to_owned(),
            "雪 ☃".to_owned(),
            "double \" and single ' quotes".to_owned(),
            r"trailing slash\".to_owned(),
            r"C:\Program Files\1C".to_owned(),
            "semi;colon & ampersand".to_owned(),
            "line one\nline two".to_owned(),
            "Srvr=server;Ref=base;Pwd=DATA".to_owned(),
            "final".to_owned(),
        ];
        let cwd = Some("C:\\owned work\\cwd".to_owned());
        let env = BTreeMap::from([("ECHO_ENV".to_owned(), "value with spaces ☃".to_owned())]);

        let requests = [
            exec_request_kind(
                ExecRequest {
                    program: "argv-echo-fixture".to_owned(),
                    args: args.clone(),
                    cwd: cwd.clone(),
                    env: env.clone(),
                    secret_env: SecretEnvironment::default(),
                    stdin: None,
                    results: Vec::new(),
                    timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
                    raw_output: false,
                },
                None,
            ),
            job_start_request_kind(JobStartRequest {
                program: "argv-echo-fixture".to_owned(),
                args: args.clone(),
                cwd: cwd.clone(),
                env: env.clone(),
                secret_env: SecretEnvironment::default(),
                stdin: None,
                results: Vec::new(),
                run_local: None,
            }),
        ];

        for request in requests {
            let wire = serde_json::to_vec(&AgentRequest::new("test-token", request))
                .expect("serialize authenticated request");
            let decoded: AgentRequest = serde_json::from_slice(&wire).expect("decode request");
            match decoded.request {
                AgentRequestKind::Exec {
                    program,
                    args: decoded_args,
                    cwd: decoded_cwd,
                    env: decoded_env,
                    ..
                }
                | AgentRequestKind::JobStart {
                    program,
                    args: decoded_args,
                    cwd: decoded_cwd,
                    env: decoded_env,
                    ..
                } => {
                    assert_eq!(program, "argv-echo-fixture");
                    assert_eq!(decoded_args, args);
                    assert_eq!(decoded_cwd, cwd);
                    assert_eq!(decoded_env, env);
                }
                other => panic!("unexpected request kind: {other:?}"),
            }
        }
    }

    #[test]
    fn exec_response_owner_must_match_the_request_generated_id() {
        let response = AgentResponseKind::Exec {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            result_set: Some(
                hostlink_protocol::ResultSetInfo::try_new(
                    hostlink_protocol::ResultOwner::exec("different-request").expect("valid owner"),
                    Vec::new(),
                )
                .expect("valid result set"),
            ),
            stdout_base64: None,
            stderr_base64: None,
        };
        assert!(validate_exec_result_owner(&response, Some("request-id")).is_err());
        assert!(validate_exec_result_owner(&response, None).is_ok());
    }
}
