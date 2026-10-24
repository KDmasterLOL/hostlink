use super::execution_evidence::{
    RECEIPT_DIRECTORY_ENV, RunLocalExecutionEvidence, output_sha256, reported_passed_test_count,
    target_triple, write_create_new_with_output,
};
use super::jobs::parse_env;
use super::*;
use base64::Engine as _;
use sha2::Digest as _;
use std::io;
use std::io::Write as _;
use std::str::FromStr as _;
use std::time::{Duration, Instant};

const RUN_LOCAL_TIMINGS_ENV: &str = "ONEC_ACCESS_RUN_LOCAL_TIMINGS";
const RUN_LOCAL_ARTIFACT_STAGING_DEADLINE: Duration = Duration::from_secs(180);
pub(super) const MAX_RUN_LOCAL_STAGING_DEADLINE: Duration = Duration::from_secs(540);
// Allow a second pre-submission approved-route pass without unbounded cleanup.
const RUN_LOCAL_CLEANUP_DEADLINE: Duration = Duration::from_secs(30);

/// Bounds one source-exact run's sequential cache probes, uploads and verification.
pub(super) struct StageBudget {
    deadline: tokio::time::Instant,
    artifact_count: u64,
    total_bytes: u64,
    allocated: Duration,
}

impl StageBudget {
    pub(super) fn for_artifact_sizes(
        artifact_sizes: impl IntoIterator<Item = u64>,
    ) -> AppResult<Self> {
        let mut artifact_count = 0_u64;
        let mut total_bytes = 0_u64;
        for bytes in artifact_sizes {
            artifact_count = artifact_count
                .checked_add(1)
                .ok_or_else(|| crate::invalid_config("too many run-local artifacts".to_owned()))?;
            total_bytes = total_bytes.checked_add(bytes).ok_or_else(|| {
                crate::invalid_config("run-local artifact byte total overflow".to_owned())
            })?;
        }
        if artifact_count == 0 {
            return Err(crate::invalid_config(
                "run-local staging requires at least one artifact".to_owned(),
            ));
        }

        let allocated = staging_budget_for_artifact_count(
            artifact_count,
            RUN_LOCAL_ARTIFACT_STAGING_DEADLINE,
            MAX_RUN_LOCAL_STAGING_DEADLINE,
        );
        Ok(Self {
            deadline: tokio::time::Instant::now() + allocated,
            artifact_count,
            total_bytes,
            allocated,
        })
    }

    pub(super) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    fn report(&self, timings_enabled: bool) {
        if timings_enabled {
            let _ = writeln!(
                std::io::stderr().lock(),
                "onec-access run-local staging budget: artifacts={} bytes={} deadline_ms={}",
                self.artifact_count,
                self.total_bytes,
                self.allocated.as_millis(),
            );
        }
    }
}

fn staging_budget_for_artifact_count(
    artifact_count: u64,
    per_artifact: Duration,
    maximum: Duration,
) -> Duration {
    let slots = u32::try_from(artifact_count).unwrap_or(u32::MAX);
    per_artifact.saturating_mul(slots).min(maximum)
}

#[derive(Clone, Copy)]
#[repr(usize)]
enum RunLocalTimingStage {
    LocalHashes,
    HubResolve,
    Lease,
    AgentPathPrepare,
    CacheAdmission,
    Upload,
    CacheRaceValidation,
    PublishedVerification,
    Exec,
    Cleanup,
}

impl RunLocalTimingStage {
    const COUNT: usize = 10;

    fn label(self) -> &'static str {
        match self {
            Self::LocalHashes => "local_hashes",
            Self::HubResolve => "hub_resolve",
            Self::Lease => "lease",
            Self::AgentPathPrepare => "agent_path_prepare",
            Self::CacheAdmission => "cache_admission",
            Self::Upload => "upload",
            Self::CacheRaceValidation => "cache_race_validation",
            Self::PublishedVerification => "published_verification",
            Self::Exec => "exec",
            Self::Cleanup => "cleanup",
        }
    }
}

struct RunLocalTimings {
    started: Instant,
    elapsed: [Duration; RunLocalTimingStage::COUNT],
    cache_hits: u64,
    cache_reused_bytes: u64,
    completed_uploads: u64,
    uploaded_bytes: u64,
}

impl RunLocalTimings {
    fn from_env_value(value: Option<&std::ffi::OsStr>) -> Option<Self> {
        value.is_some_and(|value| value == "1").then(|| Self {
            started: Instant::now(),
            elapsed: [Duration::ZERO; RunLocalTimingStage::COUNT],
            cache_hits: 0,
            cache_reused_bytes: 0,
            completed_uploads: 0,
            uploaded_bytes: 0,
        })
    }

    fn record_cache_hit(&mut self, bytes: u64) {
        self.cache_hits += 1;
        self.cache_reused_bytes = self.cache_reused_bytes.saturating_add(bytes);
    }

    fn record_completed_upload(&mut self, bytes: u64) {
        self.completed_uploads += 1;
        self.uploaded_bytes = self.uploaded_bytes.saturating_add(bytes);
    }
}

impl Drop for RunLocalTimings {
    fn drop(&mut self) {
        // Diagnostics are opt-in and must never turn an operation failure into
        // a panic if stderr has been closed by the invoking test runner.
        let _ = writeln!(
            std::io::stderr().lock(),
            "onec-access run-local timing (us): total={} local_hashes={} hub_resolve={} lease={} agent_path_prepare={} cache_admission={} upload={} cache_race_validation={} published_verification={} exec={} cleanup={} cache_hits={} cache_reused_bytes={} completed_uploads={} uploaded_bytes={}",
            self.started.elapsed().as_micros(),
            self.elapsed[RunLocalTimingStage::LocalHashes as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::HubResolve as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::Lease as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::AgentPathPrepare as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::CacheAdmission as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::Upload as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::CacheRaceValidation as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::PublishedVerification as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::Exec as usize].as_micros(),
            self.elapsed[RunLocalTimingStage::Cleanup as usize].as_micros(),
            self.cache_hits,
            self.cache_reused_bytes,
            self.completed_uploads,
            self.uploaded_bytes,
        );
    }
}

fn report_run_local_outcome(
    timings: Option<&RunLocalTimings>,
    stage: &'static str,
    outcome: &'static str,
) {
    if timings.is_some() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "onec-access run-local outcome: {stage}={outcome}"
        );
    }
}

struct RunLocalStage<'a> {
    timings: Option<&'a mut RunLocalTimings>,
    stage: RunLocalTimingStage,
    started: Option<Instant>,
}

impl<'a> RunLocalStage<'a> {
    fn new(timings: Option<&'a mut RunLocalTimings>, stage: RunLocalTimingStage) -> Self {
        let started = timings.as_ref().map(|_| Instant::now());
        if started.is_some() {
            let _ = writeln!(
                std::io::stderr().lock(),
                "onec-access run-local phase: {} begin",
                stage.label()
            );
        }
        Self {
            timings,
            stage,
            started,
        }
    }
}

impl Drop for RunLocalStage<'_> {
    fn drop(&mut self) {
        if let (Some(timings), Some(started)) = (self.timings.as_deref_mut(), self.started) {
            let elapsed = started.elapsed();
            timings.elapsed[self.stage as usize] += elapsed;
            let _ = writeln!(
                std::io::stderr().lock(),
                "onec-access run-local phase: {} end elapsed_us={}",
                self.stage.label(),
                elapsed.as_micros()
            );
        }
    }
}

pub(super) struct ExecOptions {
    pub(super) env: Vec<String>,
    pub(super) secret_env: Vec<String>,
    pub(super) stdin_file: Option<PathBuf>,
    pub(super) results: Vec<String>,
    pub(super) result_dir: Option<PathBuf>,
    pub(super) timeout_ms: u64,
}

pub(super) struct RunLocalOptions {
    pub(super) required_effect: ManagedTargetEffect,
    pub(super) cwd: Option<String>,
    pub(super) ordinary_env: Vec<String>,
    pub(super) secret_bindings: Vec<String>,
    pub(super) mapped_env: Vec<String>,
    pub(super) timeout_ms: u64,
}

/// Reports cancellation without claiming that remote asynchronous cleanup completed.
struct RunLocalCleanupNotice {
    run_id: String,
    confirmed: bool,
}

impl Drop for RunLocalCleanupNotice {
    fn drop(&mut self) {
        if !self.confirmed {
            let _ = writeln!(
                std::io::stderr().lock(),
                "onec-access run-local cleanup: state=unconfirmed run_id={}",
                self.run_id
            );
        }
    }
}

pub(super) async fn exec(
    name: String,
    cwd: Option<String>,
    options: ExecOptions,
    command: Vec<String>,
) -> AppResult<()> {
    let ExecOptions {
        env,
        secret_env,
        stdin_file,
        results,
        result_dir,
        timeout_ms,
    } = options;
    let mut command = command.into_iter();
    let program = command
        .next()
        .ok_or_else(|| crate::invalid_config("exec requires a program".to_owned()))?;
    let args = command.collect::<Vec<_>>();
    let env = parse_env(&env)?;
    let secret_env = super::secrets::resolve_secret_env(&secret_env, &env)?;
    let stdin = super::input::read_stdin_payload(stdin_file)?;
    let results = super::jobs::parse_result_specs(&results)?;
    if results.is_empty() != result_dir.is_none() {
        return Err(crate::invalid_config(
            "--result-dir must be supplied exactly when --result is used".to_owned(),
        ));
    }
    let server = resolve_remote_server(&name).await?;
    let client = RemoteAgentClient::new(server)?;
    let response = client
        .exec(&program)
        .args(args)
        .maybe_cwd(cwd)
        .timeout_ms(timeout_ms)
        .env(env)
        .secret_env(secret_env)
        .maybe_stdin(stdin)
        .results(results.clone())
        .call()
        .await?;
    let AgentResponseKind::Exec {
        exit_code,
        stdout,
        stderr,
        result_set,
        ..
    } = response
    else {
        return Err(crate::invalid_config(
            "remote agent returned a non-exec response".to_owned(),
        ));
    };
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    if !results.is_empty() {
        let result_set = result_set.ok_or_else(|| {
            crate::invalid_config("remote exec omitted declared result metadata".to_owned())
        })?;
        if result_set.owner().exec_id().is_none()
            || result_set.artifacts().len() != results.len()
            || results.iter().any(|declared| {
                !result_set.artifacts().iter().any(|published| {
                    published.name().eq_ignore_ascii_case(declared.name())
                        && published.bytes() <= declared.max_bytes()
                })
            })
        {
            return Err(crate::invalid_config(
                "remote exec result metadata does not match its declarations".to_owned(),
            ));
        }
        super::jobs::download_result_set(
            &client,
            &result_set,
            result_dir.as_deref().expect("required with results"),
            false,
            true,
        )
        .await?;
    }
    match exit_code {
        Some(0) => Ok(()),
        code => Err(crate::process_failed_error(
            PathBuf::from(format!("remote:{name}:{program}")),
            "managed exec".to_owned(),
            code,
            stderr,
        )),
    }
}

pub(super) async fn run_local(
    target: Option<String>,
    options: RunLocalOptions,
    command: Vec<String>,
) -> AppResult<i32> {
    let evidence_dir = std::env::var_os(RECEIPT_DIRECTORY_ENV).map(std::path::PathBuf::from);
    if evidence_dir
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err(crate::invalid_config(format!(
            "{RECEIPT_DIRECTORY_ENV} must be an absolute path"
        )));
    }
    let mut timings =
        RunLocalTimings::from_env_value(std::env::var_os(RUN_LOCAL_TIMINGS_ENV).as_deref());
    let RunLocalOptions {
        required_effect,
        cwd,
        ordinary_env,
        secret_bindings,
        mapped_env,
        timeout_ms,
    } = options;
    let target = target
        .or_else(|| std::env::var("ONEC_ACCESS_TARGET").ok())
        .filter(|target| !target.trim().is_empty())
        .ok_or_else(|| {
            crate::invalid_config("run-local requires --target or ONEC_ACCESS_TARGET".to_owned())
        })?;
    let (executable, args) = command
        .split_first()
        .ok_or_else(|| crate::invalid_config("run-local requires a local executable".to_owned()))?;
    let executable = PathBuf::from(executable);
    let executable = local_regular_file(executable).await?;
    let receipt_filter = if evidence_dir.is_some() {
        Some(
            onec_agent_protocol::requested_exact_testcase(args)
                .ok_or_else(|| {
                    crate::invalid_config(
                        "run-local execution evidence requires one unambiguous bounded --exact libtest filter and forbids --list and --skip"
                            .to_owned(),
                    )
                })?
                .to_owned(),
        )
    } else {
        None
    };
    let receipt_selected_platform_version = receipt_filter.as_ref().and_then(|_| {
        ordinary_env
            .iter()
            .filter_map(|binding| binding.split_once('='))
            .find(|(name, _)| name.eq_ignore_ascii_case("ONEC_NATIVE_PLATFORM_VERSION"))
            .map(|(_, value)| value.to_owned())
    });
    let receipt_target_triple = if receipt_filter.is_some() {
        Some(target_triple(&executable).ok_or_else(|| {
            crate::invalid_config(
                "run-local execution evidence requires a maintained Windows target triple in the test binary path"
                    .to_owned(),
            )
        })?)
    } else {
        None
    };
    let receipt_worktree_head_sha = match (receipt_filter.is_some(), evidence_dir.as_deref()) {
        (true, Some(directory)) => {
            require_evidence_directory_outside_source(directory)?;
            Some(current_clean_controller_worktree_head_sha()?)
        }
        (true, None) => {
            return Err(crate::invalid_config(
                "run-local evidence filter has no evidence directory".to_owned(),
            ));
        }
        (false, _) => None,
    };
    let receipt_runner_sha256 = if receipt_filter.is_some() {
        let runner = std::env::current_exe().map_err(|error| {
            crate::invalid_config(format!("cannot resolve run-local executable: {error}"))
        })?;
        Some(
            hostlink_core::FileDigest::from_path(runner)
                .map_err(|error| {
                    crate::invalid_config(format!("cannot hash run-local executable: {error}"))
                })?
                .sha256()
                .to_owned(),
        )
    } else {
        None
    };
    let mut env = parse_env(&ordinary_env)?;
    let secret_env = super::secrets::resolve_secret_env(&secret_bindings, &env)?;
    let mut staged_files = vec![(executable.clone(), None::<String>)];
    let mut mapped_names = std::collections::HashSet::new();
    for name in mapped_env {
        super::secrets::validate_environment_name(&name)?;
        if !mapped_names.insert(name.to_ascii_uppercase())
            || env
                .keys()
                .any(|existing| existing.eq_ignore_ascii_case(&name))
            || secret_env
                .keys()
                .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            return Err(crate::invalid_config(format!(
                "--map-file-env variable {name:?} is duplicated or supplied by another environment option"
            )));
        }
        let path = std::env::var_os(&name).ok_or_else(|| {
            crate::invalid_config(format!(
                "--map-file-env source environment variable {name:?} is not set"
            ))
        })?;
        let path = local_regular_file(PathBuf::from(path)).await?;
        staged_files.push((path, Some(name)));
    }

    let mut staged = Vec::with_capacity(staged_files.len());
    {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::LocalHashes);
        for (local, remote_env) in staged_files {
            let identity = hostlink_core::FileDigest::from_path(&local).map_err(|source| {
                crate::invalid_config(format!(
                    "cannot hash local file {}: {source}",
                    local.display()
                ))
            })?;
            let remote_name = content_cache_name(&local, identity.sha256());
            staged.push((local, remote_name, remote_env, identity));
        }
    }

    let (hub, agent) = {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::HubResolve);
        let config_path = hub_config_path()?;
        let hub = HubClient::configured()?.ok_or_else(|| {
            crate::not_found_error(format!(
                "onec-access config {}; configure access before using remote operations",
                config_path.display()
            ))
        })?;
        let agent = hub
            .resolve_agent(&target)
            .await?
            .ok_or_else(|| crate::not_found_error(format!("hub-managed host {target:?}")))?;
        (hub, agent)
    };
    let _mutable_lease = {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::Lease);
        super::mutable_lease::acquire_run_local_lease(&agent.machine_id, required_effect, args)?
    };
    let server = {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::HubResolve);
        hub.resolve_remote_server_for_machine(&agent.machine_id)
            .await?
    };
    let client = RemoteAgentClient::new(server)?;
    let receipt_host = if receipt_filter.is_some() {
        match client.hello().await? {
            AgentResponseKind::Hello { hostname, os, .. }
                if !hostname.trim().is_empty() && !os.trim().is_empty() =>
            {
                Some((hostname, os))
            }
            _ => {
                return Err(crate::invalid_config(
                    "run-local execution evidence requires a complete authenticated agent Hello"
                        .to_owned(),
                ));
            }
        }
    } else {
        None
    };
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let run_paths = {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::AgentPathPrepare);
        client.prepare_run_local(run_id.clone()).await?
    };
    let mut cleanup_notice = RunLocalCleanupNotice {
        run_id,
        confirmed: false,
    };
    let stage_budget =
        StageBudget::for_artifact_sizes(staged.iter().map(|(_, _, _, identity)| identity.bytes()))?;
    stage_budget.report(timings.is_some());
    let staging_deadline = stage_budget.deadline();
    let mut terminal_exit_code = None;
    let mut terminal_reported_passed_test_count = None;
    let mut terminal_stdout_sha256 = None;
    let mut terminal_stderr_sha256 = None;
    let mut terminal_stdout = None;
    let mut terminal_stderr = None;
    let operation = async {
        let staged_paths = tokio::time::timeout_at(staging_deadline, async {
            let mut remote_executable = None;
            for (local, remote_name, remote_env, identity) in &staged {
                let remote_path = join_remote_path(&run_paths.cache_root, remote_name);
                publish_or_reuse_timed(
                    &client,
                    local,
                    &remote_path,
                    identity,
                    timings.as_mut(),
                )
                .await?;
                if let Some(name) = remote_env {
                    env.insert(name.clone(), remote_path.clone());
                } else {
                    remote_executable = Some(remote_path);
                }
            }
            Ok::<_, anyhow::Error>(remote_executable)
        })
        .await
        .map_err(|_| {
            report_run_local_outcome(timings.as_ref(), "staging", "deadline_exceeded_unknown");
            crate::invalid_config(
                "run-local staging deadline exceeded (phase=staging; remote_state=unknown)"
                    .to_owned(),
            )
        })??;
        let remote_executable = staged_paths;
        let program = remote_executable.expect("the executable is staged first");
        let response = {
            let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::Exec);
            client
                .exec(program)
                .args(args.to_vec())
                .cwd(cwd.unwrap_or_else(|| run_paths.run_root.clone()))
                .timeout_ms(timeout_ms)
                .raw_output(true)
                .env(env)
                .secret_env(secret_env)
                .call()
                .await?
        };
        let AgentResponseKind::Exec {
            exit_code,
            stdout_base64: Some(stdout),
            stderr_base64: Some(stderr),
            ..
        } = response
        else {
            return Err(crate::invalid_config(
                "remote agent returned an exec response without raw output".to_owned(),
            ));
        };
        terminal_exit_code = Some(exit_code);
        let stdout = base64::engine::general_purpose::STANDARD
            .decode(stdout)
            .map_err(|error| {
                crate::invalid_config(format!("invalid raw stdout encoding: {error}"))
            })?;
        let stderr = base64::engine::general_purpose::STANDARD
            .decode(stderr)
            .map_err(|error| {
                crate::invalid_config(format!("invalid raw stderr encoding: {error}"))
            })?;
        // Hash the exact decoded bytes before writing them or interpreting any child text.
        terminal_stdout_sha256 = Some(output_sha256(&stdout));
        terminal_stderr_sha256 = Some(output_sha256(&stderr));
        validate_run_local_output_size(stdout.len(), stderr.len(), evidence_dir.is_some())?;
        if evidence_dir.is_some() && exit_code == Some(0) {
            terminal_stdout = Some(stdout.clone());
            terminal_stderr = Some(stderr.clone());
        }
        let mut local_stdout = std::io::stdout().lock();
        let mut local_stderr = std::io::stderr().lock();
        forward_run_local_output(&stdout, &stderr, &mut local_stdout, &mut local_stderr)
            .map_err(|(stream, error)| {
                crate::invalid_config(format!("failed to write child {stream}: {error}"))
            })?;
        if evidence_dir.is_some() && exit_code == Some(0) {
            terminal_reported_passed_test_count = Some(reported_passed_test_count(&stdout, &stderr).ok_or_else(
                || {
                    crate::invalid_config(
                        "run-local execution evidence requires one terminal non-empty libtest success summary"
                            .to_owned(),
                    )
                },
            )?);
        }
        Ok(exit_code.unwrap_or(1))
    }
    .await;
    let cleanup = {
        let _stage = RunLocalStage::new(timings.as_mut(), RunLocalTimingStage::Cleanup);
        match tokio::time::timeout(
            RUN_LOCAL_CLEANUP_DEADLINE,
            client.path_remove_scoped(&run_paths.run_root_parent, &run_paths.run_root, true, true),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::invalid_config(
                "run-local cleanup deadline exceeded (state=unconfirmed)".to_owned(),
            )),
        }
    };
    if cleanup.is_ok() {
        cleanup_notice.confirmed = true;
    }
    match (operation, cleanup) {
        (Ok(code), Ok(_)) => {
            if let (
                Some(directory),
                Some(filter),
                Some(target),
                Some(source),
                Some(runner),
                Some((hostname, os)),
            ) = (
                evidence_dir.as_deref(),
                receipt_filter.as_deref(),
                receipt_target_triple,
                receipt_worktree_head_sha,
                receipt_runner_sha256,
                receipt_host,
            ) {
                let exit_code = terminal_exit_code.flatten();
                if exit_code != Some(0) {
                    return Ok(code);
                }
                let reported_passed_test_count = terminal_reported_passed_test_count.ok_or_else(|| {
                    crate::invalid_config(
                        "run-local observation has no matching non-empty reported libtest transcript"
                            .to_owned(),
                    )
                })?;
                let executable_identity = staged
                    .first()
                    .map(|(_, _, _, identity)| identity)
                    .ok_or_else(|| {
                        crate::invalid_config(
                            "run-local evidence has no staged test binary".to_owned(),
                        )
                    })?;
                let executable_after =
                    hostlink_core::FileDigest::from_path(&executable).map_err(|_| {
                        crate::invalid_config("cannot recheck run-local test binary".to_owned())
                    })?;
                if executable_after.sha256() != executable_identity.sha256() {
                    return Err(crate::invalid_config(
                        "run-local test binary changed during execution".to_owned(),
                    ));
                }
                let runner_after = std::env::current_exe().map_err(|_| {
                    crate::invalid_config("cannot recheck run-local executable".to_owned())
                })?;
                let runner_after =
                    hostlink_core::FileDigest::from_path(runner_after).map_err(|_| {
                        crate::invalid_config("cannot recheck run-local executable".to_owned())
                    })?;
                if runner_after.sha256() != runner {
                    return Err(crate::invalid_config(
                        "run-local executable changed during execution".to_owned(),
                    ));
                }
                let parameters = serde_json::to_vec(&args).map_err(|error| {
                    crate::invalid_config(format!(
                        "cannot encode run-local evidence parameters: {error}"
                    ))
                })?;
                let parameters_sha256 = format!("{:x}", sha2::Sha256::digest(&parameters));
                let worktree_head_sha = current_clean_controller_worktree_head_sha()?;
                if worktree_head_sha != source {
                    return Err(crate::invalid_config(
                        "controller worktree HEAD changed while run-local evidence was being recorded"
                            .to_owned(),
                    ));
                }
                let exit_code = terminal_exit_code.flatten();
                let completed_at_unix_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|error| {
                        crate::invalid_config(format!("system clock is before Unix epoch: {error}"))
                    })?
                    .as_millis()
                    .try_into()
                    .map_err(|_| {
                        crate::invalid_config("run-local evidence timestamp overflow".to_owned())
                    })?;
                let evidence = RunLocalExecutionEvidence {
                    schema_version: 3,
                    toolkit_version: env!("CARGO_PKG_VERSION").to_owned(),
                    run_id: cleanup_notice.run_id.clone(),
                    observed_controller_worktree_head_sha: source,
                    runner_sha256: hostlink_core::Sha256Digest::from_str(&runner).map_err(
                        |error| {
                            crate::invalid_config(format!(
                                "invalid run-local runner digest: {error}"
                            ))
                        },
                    )?,
                    test_binary_sha256: hostlink_core::Sha256Digest::from_str(
                        executable_identity.sha256(),
                    )
                    .map_err(|error| {
                        crate::invalid_config(format!(
                            "invalid run-local test binary digest: {error}"
                        ))
                    })?,
                    host_id: agent.machine_id.clone(),
                    host_name: hostname,
                    host_os: os,
                    target_triple: target.to_owned(),
                    effect: required_effect.as_str().to_owned(),
                    selected_platform_version: receipt_selected_platform_version,
                    test_filter: filter.to_owned(),
                    parameters_sha256: hostlink_core::Sha256Digest::from_str(&parameters_sha256)
                        .map_err(|error| {
                            crate::invalid_config(format!(
                                "invalid run-local parameters digest: {error}"
                            ))
                        })?,
                    stdout_sha256: terminal_stdout_sha256,
                    stderr_sha256: terminal_stderr_sha256,
                    exit_code,
                    reported_passed_test_count,
                    completed_at_unix_ms,
                };
                let stdout = terminal_stdout.as_deref().ok_or_else(|| {
                    crate::invalid_config("run-local evidence has no captured stdout".to_owned())
                })?;
                let stderr = terminal_stderr.as_deref().ok_or_else(|| {
                    crate::invalid_config("run-local evidence has no captured stderr".to_owned())
                })?;
                let receipt = write_create_new_with_output(directory, &evidence, stdout, stderr)
                    .map_err(|_| {
                        crate::invalid_config(
                            "cannot create run-local execution evidence".to_owned(),
                        )
                    })?;
                eprintln!("run-local observation written: {}", receipt.display());
            }
            Ok(code)
        }
        (Err(operation), Ok(_)) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup.context("failed to clean run-local state")),
        (Err(operation), Err(cleanup)) => {
            Err(operation.context(format!("run-local state cleanup also failed: {cleanup:#}")))
        }
    }
}

fn validate_run_local_output_size(
    stdout_len: usize,
    stderr_len: usize,
    evidence_enabled: bool,
) -> AppResult<()> {
    let maximum = super::execution_evidence::MAX_RAW_OUTPUT_BYTES;
    if stdout_len > maximum || stderr_len > maximum {
        let kind = if evidence_enabled { "evidence " } else { "" };
        return Err(crate::invalid_config(format!(
            "run-local raw output exceeds the 4 MiB per-stream {kind}limit"
        )));
    }
    Ok(())
}

fn forward_run_local_output<WOut: io::Write, WErr: io::Write>(
    stdout: &[u8],
    stderr: &[u8],
    local_stdout: &mut WOut,
    local_stderr: &mut WErr,
) -> Result<(), (&'static str, io::Error)> {
    local_stdout
        .write_all(stdout)
        .map_err(|error| ("stdout", error))?;
    local_stderr
        .write_all(stderr)
        .map_err(|error| ("stderr", error))
}

#[cfg(test)]
async fn execute_after_staging<T, R, SF, EF, F>(staging: SF, execute: F) -> AppResult<R>
where
    SF: std::future::Future<Output = AppResult<T>>,
    F: FnOnce(T) -> EF,
    EF: std::future::Future<Output = AppResult<R>>,
{
    let staged = staging.await?;
    execute(staged).await
}

pub(super) async fn local_regular_file(path: PathBuf) -> AppResult<PathBuf> {
    let inspect_path = path.clone();
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::symlink_metadata(&inspect_path).map_err(|source| {
            crate::invalid_config(format!(
                "cannot inspect local file {}: {source}",
                inspect_path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(crate::invalid_config(format!(
                "local executable or mapped environment path is not a regular file: {}",
                inspect_path.display()
            )));
        }
        std::fs::File::open(&inspect_path).map_err(|source| {
            crate::invalid_config(format!(
                "cannot open local file {}: {source}",
                inspect_path.display()
            ))
        })?;
        Ok(inspect_path)
    })
    .await
    .map_err(|error| crate::invalid_config(format!("local file check failed: {error}")))?
}

// Local source-identification Git calls must not inherit agent, hub, or
// infobase credentials simply because the controller has resolved them.
fn source_git_command() -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "XDG_CONFIG_HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

fn current_clean_controller_worktree_head_sha() -> AppResult<String> {
    let head = source_git_command()
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .map_err(|error| {
            crate::invalid_config(format!("cannot inspect source revision: {error}"))
        })?;
    if !head.status.success() {
        return Err(crate::invalid_config(
            "cannot resolve source revision".to_owned(),
        ));
    }
    let sha = String::from_utf8(head.stdout)
        .map_err(|error| crate::invalid_config(format!("source revision is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if sha.len() != 40 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::invalid_config(
            "source revision is not a full Git commit SHA".to_owned(),
        ));
    }
    let status = source_git_command()
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|error| {
            crate::invalid_config(format!("cannot inspect source worktree: {error}"))
        })?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(crate::invalid_config(
            "run-local execution evidence requires a clean source worktree".to_owned(),
        ));
    }
    Ok(sha)
}

fn require_evidence_directory_outside_source(directory: &std::path::Path) -> AppResult<()> {
    let root = source_git_command()
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| crate::invalid_config(format!("cannot inspect source root: {error}")))?;
    if !root.status.success() {
        return Err(crate::invalid_config(
            "cannot resolve source root".to_owned(),
        ));
    }
    let root = std::path::PathBuf::from(
        String::from_utf8(root.stdout)
            .map_err(|error| crate::invalid_config(format!("source root is not UTF-8: {error}")))?
            .trim(),
    );
    let root = std::fs::canonicalize(root)
        .map_err(|error| crate::invalid_config(format!("cannot resolve source root: {error}")))?;
    let mut existing = directory;
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| {
            crate::invalid_config(
                "run-local evidence directory has no existing ancestor".to_owned(),
            )
        })?;
    }
    let existing = std::fs::canonicalize(existing).map_err(|error| {
        crate::invalid_config(format!("cannot resolve evidence directory: {error}"))
    })?;
    if existing.starts_with(root) {
        return Err(crate::invalid_config(
            "run-local evidence directory must be outside the source worktree".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn content_cache_name(path: &std::path::Path, digest: &str) -> String {
    let extension = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|extension| {
            !extension.is_empty() && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        });
    match extension {
        Some(extension) => format!("sha256-{digest}.{extension}"),
        None => format!("sha256-{digest}"),
    }
}

pub(super) fn join_remote_path(root: &str, name: &str) -> String {
    let separator = if root.contains('\\') { '\\' } else { '/' };
    format!("{}{separator}{name}", root.trim_end_matches(['\\', '/']))
}

pub(super) async fn publish_or_reuse(
    client: &RemoteAgentClient,
    local: &std::path::Path,
    remote: &str,
    identity: &hostlink_core::FileDigest,
) -> AppResult<()> {
    publish_or_reuse_timed(client, local, remote, identity, None).await
}

/// Requires an exact Agent-owned cache entry and never attempts a transfer.
pub(super) async fn require_cached_candidate(
    client: &RemoteAgentClient,
    remote: &str,
    identity: &hostlink_core::FileDigest,
    phase: &'static str,
) -> AppResult<()> {
    let observed = client.path_sha256(remote.to_owned()).await;
    verify_cached_candidate_probe(phase, identity, observed)
}

fn verify_cached_candidate_probe(
    phase: &'static str,
    expected: &hostlink_core::FileDigest,
    observed: AppResult<(u64, String)>,
) -> AppResult<()> {
    let (actual_bytes, actual_digest) = observed.map_err(|_| {
        anyhow::anyhow!(
            "required run-local cache entry is missing or unreadable; Agent PathSha256 verification failed and upload was not attempted"
        )
    })?;
    if actual_bytes != expected.bytes() || actual_digest != expected.sha256() {
        return Err(run_local_cache_mismatch_error(
            phase,
            expected.bytes(),
            expected.sha256(),
            actual_bytes,
            &actual_digest,
        ));
    }
    Ok(())
}

async fn publish_or_reuse_timed(
    client: &RemoteAgentClient,
    local: &std::path::Path,
    remote: &str,
    identity: &hostlink_core::FileDigest,
    timings: Option<&mut RunLocalTimings>,
) -> AppResult<()> {
    let mut timings = timings;
    // This is the identity that named the remote destination, not a second,
    // potentially newer read of the local path. Upload verification must be
    // against the original identity even when the source changes concurrently.
    let expected_size = identity.bytes();
    let expected_digest = identity.sha256();

    // run-local-cache is shared across run IDs. Reuse a candidate only after checking both
    // identity fields; attempting upload first needlessly opens a transfer and can send the
    // complete file before the non-overwrite publication rejects the existing cache entry.
    let cached = {
        let _stage =
            RunLocalStage::new(timings.as_deref_mut(), RunLocalTimingStage::CacheAdmission);
        client.path_sha256_if_present(remote.to_owned()).await
    };
    let admission = admit_run_local_cache(cached, expected_size, expected_digest, || async {
        report_run_local_outcome(timings.as_deref(), "cache_admission", "missing");
        let _stage = RunLocalStage::new(timings.as_deref_mut(), RunLocalTimingStage::Upload);
        client.upload(local, remote.to_owned(), false).await
    })
    .await;
    match admission {
        Ok(CacheAdmission::Match) => {
            if let Some(timings) = timings.as_deref_mut() {
                timings.record_cache_hit(expected_size);
            }
            report_run_local_outcome(timings.as_deref(), "cache_admission", "exact_match");
            return Ok(());
        }
        Ok(CacheAdmission::Corrupt {
            actual_bytes,
            actual_digest,
        }) => {
            report_run_local_outcome(timings.as_deref(), "cache_admission", "corrupt");
            return Err(run_local_cache_mismatch_error(
                "cache_admission",
                expected_size,
                expected_digest,
                actual_bytes,
                &actual_digest,
            ));
        }
        Ok(CacheAdmission::UploadComplete(uploaded_bytes)) => {
            if let Some(timings) = timings.as_deref_mut() {
                timings.record_completed_upload(uploaded_bytes);
            }
            report_run_local_outcome(timings.as_deref(), "upload", "complete");
        }
        Ok(CacheAdmission::UploadFailed(upload_error)) => {
            report_run_local_outcome(timings.as_deref(), "upload", "failed");
            let validation = {
                let _stage = RunLocalStage::new(
                    timings.as_deref_mut(),
                    RunLocalTimingStage::CacheRaceValidation,
                );
                client.path_sha256(remote.to_owned()).await
            };
            match validation {
                Ok((bytes, digest)) if bytes == expected_size && digest == expected_digest => {
                    report_run_local_outcome(
                        timings.as_deref(),
                        "cache_race_validation",
                        "exact_match",
                    );
                    return Ok(());
                }
                Ok((bytes, digest)) => {
                    report_run_local_outcome(
                        timings.as_deref(),
                        "cache_race_validation",
                        "corrupt",
                    );
                    return Err(run_local_cache_mismatch_error(
                        "cache_race_validation",
                        expected_size,
                        expected_digest,
                        bytes,
                        &digest,
                    ));
                }
                Err(_) => {
                    report_run_local_outcome(
                        timings.as_deref(),
                        "cache_race_validation",
                        "unavailable",
                    );
                    return Err(upload_error);
                }
            }
        }
        Err(error) => {
            report_run_local_outcome(timings.as_deref(), "cache_admission", "unavailable");
            return Err(run_local_cache_admission_error(error));
        }
    }
    let published = {
        let _stage = RunLocalStage::new(
            timings.as_deref_mut(),
            RunLocalTimingStage::PublishedVerification,
        );
        client.path_sha256(remote.to_owned()).await
    };
    let (bytes, digest) = match published {
        Ok(identity) => identity,
        Err(error) => {
            report_run_local_outcome(timings.as_deref(), "published_verification", "unavailable");
            return Err(error);
        }
    };
    if bytes != expected_size || digest != expected_digest {
        report_run_local_outcome(timings.as_deref(), "published_verification", "corrupt");
        return Err(run_local_cache_mismatch_error(
            "published_verification",
            expected_size,
            expected_digest,
            bytes,
            &digest,
        ));
    }
    report_run_local_outcome(timings.as_deref(), "published_verification", "exact_match");
    Ok(())
}

// The cache path may contain an operator-provided filename. Remote digests are
// untrusted protocol values, so only bounded SHA-256 syntax is safe to display.
fn run_local_cache_mismatch_error(
    phase: &'static str,
    expected_bytes: u64,
    expected_digest: &str,
    actual_bytes: u64,
    actual_digest: &str,
) -> AppError {
    let actual_digest = if actual_digest.len() == 64
        && actual_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        actual_digest
    } else {
        "<invalid-sha256>"
    };
    crate::invalid_config(format!(
        "run-local cache {phase} identity mismatch: expected {expected_bytes} bytes / {expected_digest}, got {actual_bytes} bytes / {actual_digest}"
    ))
}

fn run_local_cache_admission_error(error: AppError) -> AppError {
    anyhow::anyhow!("cannot verify run-local cache entry; upload skipped: {error}")
}

#[derive(Debug, PartialEq, Eq)]
enum CachedContent {
    Missing,
    Match,
    Corrupt {
        actual_bytes: u64,
        actual_digest: String,
    },
}

#[derive(Debug)]
enum CacheAdmission {
    Match,
    Corrupt {
        actual_bytes: u64,
        actual_digest: String,
    },
    UploadComplete(u64),
    UploadFailed(anyhow::Error),
}

async fn admit_run_local_cache<F, Fut>(
    probe: AppResult<Option<(u64, String)>>,
    expected_size: u64,
    expected_digest: &str,
    upload: F,
) -> AppResult<CacheAdmission>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = AppResult<u64>>,
{
    match classify_cache_probe(probe, expected_size, expected_digest)? {
        CachedContent::Match => Ok(CacheAdmission::Match),
        CachedContent::Corrupt {
            actual_bytes,
            actual_digest,
        } => Ok(CacheAdmission::Corrupt {
            actual_bytes,
            actual_digest,
        }),
        CachedContent::Missing => Ok(match upload().await {
            Ok(bytes) => CacheAdmission::UploadComplete(bytes),
            Err(error) => CacheAdmission::UploadFailed(error),
        }),
    }
}

fn classify_cache_probe(
    probe: AppResult<Option<(u64, String)>>,
    expected_size: u64,
    expected_digest: &str,
) -> AppResult<CachedContent> {
    match probe {
        Ok(None) => Ok(CachedContent::Missing),
        Ok(Some((bytes, digest))) => Ok(classify_cached_content(
            Some((bytes, digest)),
            expected_size,
            expected_digest,
        )),
        Err(error) => Err(error),
    }
}

fn classify_cached_content(
    actual: Option<(u64, String)>,
    expected_bytes: u64,
    expected_digest: &str,
) -> CachedContent {
    let Some((actual_bytes, actual_digest)) = actual else {
        return CachedContent::Missing;
    };
    if actual_bytes == expected_bytes && actual_digest == expected_digest {
        CachedContent::Match
    } else {
        CachedContent::Corrupt {
            actual_bytes,
            actual_digest,
        }
    }
}

pub(super) async fn probe(name: String, host: String, port: u16, timeout_ms: u64) -> AppResult<()> {
    let response = RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .probe(host, port, timeout_ms)
        .await?;
    crate::cli::output::print_pretty_json(&response);
    Ok(())
}

pub(super) async fn upload(
    name: String,
    local: PathBuf,
    remote: String,
    overwrite: bool,
) -> AppResult<()> {
    let bytes = RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .upload(&local, remote, overwrite)
        .await?;
    println!("{} -> {name}: {bytes} bytes", local.display());
    Ok(())
}

pub(super) async fn download(
    name: String,
    remote: String,
    local: PathBuf,
    overwrite: bool,
) -> AppResult<()> {
    let bytes = RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .download(remote, &local, overwrite)
        .await?;
    println!("{name} -> {}: {bytes} bytes", local.display());
    Ok(())
}

pub(super) async fn remove_scoped(
    name: String,
    root: String,
    path: String,
    recursive: bool,
    missing_ok: bool,
    json_output: bool,
) -> AppResult<()> {
    let removed = RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .path_remove_scoped(root, path, recursive, missing_ok)
        .await?;
    if json_output {
        crate::cli::output::print_pretty_json(&json!({ "removed": removed }));
    } else if removed {
        println!("Removed managed path");
    } else {
        println!("Managed path already absent");
    }
    Ok(())
}

pub(super) async fn rdp(name: String, listen_port: u16) -> AppResult<()> {
    let listen = format!("127.0.0.1:{listen_port}")
        .parse()
        .expect("valid loopback RDP endpoint");
    println!("RDP {name}: 127.0.0.1:{listen_port} -> 127.0.0.1:3389. Ctrl+C to stop.");
    RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .forward(listen, "127.0.0.1".to_owned(), 3389)
        .await
}

pub(super) async fn forward(
    name: String,
    listen_host: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
) -> AppResult<()> {
    let listen = format!("{listen_host}:{listen_port}")
        .parse()
        .map_err(|error| {
            crate::invalid_config(format!(
                "invalid local endpoint {listen_host}:{listen_port}: {error}"
            ))
        })?;
    println!("Forward {listen} -> {name}:{target_host}:{target_port}. Ctrl+C to stop.");
    RemoteAgentClient::new(resolve_remote_server(&name).await?)?
        .forward(listen, target_host, target_port)
        .await
}

#[cfg(all(test, unix))]
mod source_git_env_tests {
    use super::source_git_command;

    #[test]
    fn source_git_child_does_not_inherit_parent_secrets() {
        const PARENT_FIXTURE: &str = "ONEC_ACCESS_SOURCE_GIT_PARENT_FIXTURE";
        if std::env::var_os(PARENT_FIXTURE).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current test executable"),
            )
            .args([
                "source_git_child_does_not_inherit_parent_secrets",
                "--nocapture",
            ])
            .env(PARENT_FIXTURE, "1")
            .env("CUSTOM_PRIVATE_CREDENTIAL", "fixture-private-secret")
            .env("ONEC_HUB_OPERATOR_TOKEN", "fixture-operator-token")
            .env("GIT_CONFIG_PARAMETERS", "'fake.from_host=true'")
            .env("LD_PRELOAD", "")
            .output()
            .expect("spawn isolated parent test process");
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "isolated parent fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let result = source_git_command()
            .args(["-c", "alias.onec-env-probe=!env", "onec-env-probe"])
            .output()
            .expect("run real Git child environment probe");
        assert!(
            result.status.success(),
            "real Git environment probe failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let environment = String::from_utf8(result.stdout).expect("UTF-8 fixture environment");
        for forbidden in [
            "CUSTOM_PRIVATE_CREDENTIAL=",
            "ONEC_HUB_OPERATOR_TOKEN=",
            "LD_PRELOAD=",
        ] {
            assert!(
                !environment.lines().any(|line| line.starts_with(forbidden)),
                "unapproved host variable inherited by Git: {forbidden}"
            );
        }
        // Git itself sets GIT_CONFIG_PARAMETERS to transport the explicit
        // '-c alias.onec-env-probe=...' into its shell alias. The host value
        // must not be present in that internally generated value.
        assert!(!environment.contains("fake.from_host=true"));
        assert!(environment.lines().any(|line| line.starts_with("PATH=")));
        assert!(environment.lines().any(|line| line.starts_with("HOME=")));
    }
}

#[cfg(test)]
mod run_local_cache_tests {
    use super::{
        CacheAdmission, CachedContent, MAX_RUN_LOCAL_STAGING_DEADLINE,
        RUN_LOCAL_ARTIFACT_STAGING_DEADLINE, RunLocalStage, RunLocalTimingStage, RunLocalTimings,
        StageBudget, admit_run_local_cache, classify_cache_probe, classify_cached_content,
        execute_after_staging, forward_run_local_output, staging_budget_for_artifact_count,
        validate_run_local_output_size, verify_cached_candidate_probe,
    };
    use std::time::Duration;

    #[test]
    fn run_local_phase_diagnostics_use_fixed_non_sensitive_labels() {
        let stages = [
            RunLocalTimingStage::LocalHashes,
            RunLocalTimingStage::HubResolve,
            RunLocalTimingStage::Lease,
            RunLocalTimingStage::AgentPathPrepare,
            RunLocalTimingStage::CacheAdmission,
            RunLocalTimingStage::Upload,
            RunLocalTimingStage::CacheRaceValidation,
            RunLocalTimingStage::PublishedVerification,
            RunLocalTimingStage::Exec,
            RunLocalTimingStage::Cleanup,
        ];
        let labels = stages.map(RunLocalTimingStage::label);
        assert_eq!(labels.len(), RunLocalTimingStage::COUNT);
        for (index, label) in labels.iter().enumerate() {
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
            assert!(!labels[..index].contains(label));
        }
        assert_eq!(labels[4], "cache_admission");
        assert_eq!(labels[5], "upload");
        assert_eq!(labels[6], "cache_race_validation");
        assert_eq!(labels[7], "published_verification");
    }

    #[test]
    fn cached_filename_and_verification_use_one_pinned_stream_identity() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("runner.exe");
        std::fs::write(&source, b"original executable bytes").expect("write source");
        let identity = hostlink_core::FileDigest::from_path(&source).expect("original identity");
        let remote = super::content_cache_name(&source, identity.sha256());

        // A source changing while the controller resolves the target must not
        // silently rebind a content-addressed filename to the newer payload.
        std::fs::write(&source, b"changed executable bytes").expect("change source");
        let changed = hostlink_core::FileDigest::from_path(&source).expect("new identity");
        assert_ne!(identity.sha256(), changed.sha256());
        assert!(remote.contains(identity.sha256()));
        assert!(!remote.contains(changed.sha256()));
        assert_eq!(
            classify_cached_content(
                Some((changed.bytes(), changed.sha256().to_owned())),
                identity.bytes(),
                identity.sha256(),
            ),
            CachedContent::Corrupt {
                actual_bytes: changed.bytes(),
                actual_digest: changed.sha256().to_owned(),
            }
        );
        assert_eq!(
            classify_cached_content(
                Some((identity.bytes(), identity.sha256().to_owned())),
                identity.bytes(),
                identity.sha256(),
            ),
            CachedContent::Match
        );
    }

    #[test]
    fn content_cache_reuse_requires_exact_size_and_sha256() {
        let digest = "a".repeat(64);
        assert_eq!(
            classify_cached_content(Some((17, digest.clone())), 17, &digest),
            CachedContent::Match
        );
        assert_eq!(
            classify_cached_content(None, 17, &digest),
            CachedContent::Missing
        );
        assert_eq!(
            classify_cached_content(Some((16, digest.clone())), 17, &digest),
            CachedContent::Corrupt {
                actual_bytes: 16,
                actual_digest: digest.clone(),
            }
        );
        assert_eq!(
            classify_cached_content(Some((17, "b".repeat(64))), 17, &digest),
            CachedContent::Corrupt {
                actual_bytes: 17,
                actual_digest: "b".repeat(64),
            }
        );
    }

    #[test]
    fn cache_probe_errors_never_become_upload_authority() {
        let digest = "a".repeat(64);
        assert_eq!(
            classify_cache_probe(Ok(None), 17, &digest).expect("typed missing"),
            CachedContent::Missing
        );
        for error in [
            crate::invalid_config("hash timeout".to_owned()),
            crate::invalid_config("access denied".to_owned()),
            crate::invalid_config("legacy agent returned untyped failure".to_owned()),
        ] {
            assert!(classify_cache_probe(Err(error), 17, &digest).is_err());
        }
        assert_eq!(
            classify_cache_probe(Ok(Some((17, digest.clone()))), 17, &digest)
                .expect("verified cache hit"),
            CachedContent::Match
        );
        assert!(matches!(
            classify_cache_probe(Ok(Some((16, digest.clone()))), 17, &digest)
                .expect("corrupt identity stays classified"),
            CachedContent::Corrupt { .. }
        ));
    }

    #[test]
    fn required_cached_candidate_accepts_only_exact_agent_path_sha256() {
        let directory = tempfile::tempdir().expect("candidate fixture");
        let candidate = directory.path().join("candidate.exe");
        std::fs::write(&candidate, b"source exact candidate").expect("write candidate");
        let expected =
            hostlink_core::FileDigest::from_path(&candidate).expect("candidate identity");
        let exact = (expected.bytes(), expected.sha256().to_owned());

        assert!(
            verify_cached_candidate_probe("cache_admission", &expected, Ok(exact.clone())).is_ok()
        );

        let absent = verify_cached_candidate_probe(
            "cache_admission",
            &expected,
            Err(crate::invalid_config("PathNotFound".to_owned())),
        )
        .expect_err("absent cache entry must fail without upload authority");
        assert!(absent.to_string().contains("missing or unreadable"));
        assert!(absent.to_string().contains("upload was not attempted"));

        for observed in [
            (
                expected.bytes().saturating_sub(1),
                expected.sha256().to_owned(),
            ),
            (expected.bytes(), "b".repeat(64)),
        ] {
            let mismatch = verify_cached_candidate_probe("pre_submission", &expected, Ok(observed))
                .expect_err("changed cache identity must fail closed");
            assert!(mismatch.to_string().contains("identity mismatch"));
        }

        let read_error = verify_cached_candidate_probe(
            "cache_admission",
            &expected,
            Err(crate::invalid_config("permission denied".to_owned())),
        )
        .expect_err("PathSha256 read errors must fail without upload");
        assert!(read_error.to_string().contains("missing or unreadable"));
        assert!(read_error.to_string().contains("upload was not attempted"));
    }

    #[test]
    fn cache_admission_cli_error_keeps_safe_cause_category() {
        let source = anyhow::anyhow!(
            "Agent PathSha256 response was opaque; TargetSftp absence proof failed: SFTP permission denied"
        );
        let rendered = format!(
            "onec-access: {}",
            super::run_local_cache_admission_error(source)
        );
        assert_eq!(
            rendered,
            "onec-access: cannot verify run-local cache entry; upload skipped: Agent PathSha256 response was opaque; TargetSftp absence proof failed: SFTP permission denied"
        );
        for private in ["token=", "/home/", "192.0.2.", "secret"] {
            assert!(
                !rendered.contains(private),
                "unexpected {private}: {rendered}"
            );
        }
    }

    #[test]
    fn cache_identity_mismatch_diagnostics_never_expose_remote_path_or_untrusted_digest() {
        let expected_digest = "a".repeat(64);
        let secret = "private-remote/cache/secret=123\\ncredential=hidden";
        for phase in [
            "cache_admission",
            "cache_race_validation",
            "published_verification",
        ] {
            let error =
                super::run_local_cache_mismatch_error(phase, 17, &expected_digest, 18, secret);
            let rendered = format!("{error:#}");
            assert!(rendered.contains(phase));
            assert!(rendered.contains("expected 17 bytes"));
            assert!(rendered.contains("got 18 bytes / <invalid-sha256>"));
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains("private-remote"));
            assert!(!rendered.contains("credential=hidden"));
        }
        let actual_digest = "b".repeat(64);
        let error = super::run_local_cache_mismatch_error(
            "published_verification",
            17,
            &expected_digest,
            18,
            &actual_digest,
        );
        assert!(error.to_string().contains(&actual_digest));
    }

    #[tokio::test]
    async fn run_local_cache_admission_controls_exact_upload_and_exec_attempts() {
        let digest = "a".repeat(64);
        let cases = [
            ("hit", Ok(Some((17, digest.clone()))), 0, 1),
            ("typed missing", Ok(None), 1, 1),
            ("corrupt", Ok(Some((16, digest.clone()))), 0, 0),
            (
                "transport failure",
                Err(crate::invalid_config("connection reset".to_owned())),
                0,
                0,
            ),
            (
                "hash timeout",
                Err(crate::invalid_config("hash timeout".to_owned())),
                0,
                0,
            ),
            (
                "permission failure",
                Err(crate::invalid_config("access denied".to_owned())),
                0,
                0,
            ),
            (
                "protocol mismatch",
                Err(crate::invalid_config("unexpected response type".to_owned())),
                0,
                0,
            ),
            (
                "legacy untyped missing",
                Err(crate::invalid_config("untyped remote failure".to_owned())),
                0,
                0,
            ),
            (
                "opaque Agent and administratively prohibited SFTP",
                Err(crate::invalid_config(
                    "Agent PathSha256 response was opaque; TargetSftp absence proof failed: SSH administratively prohibited or unauthorized"
                        .to_owned(),
                )),
                0,
                0,
            ),
            (
                "unknown SFTP error",
                Err(crate::invalid_config(
                    "Agent PathSha256 response was opaque; TargetSftp absence proof failed: unclassified SFTP transport error"
                        .to_owned(),
                )),
                0,
                0,
            ),
        ];

        for (name, probe, expected_uploads, expected_execs) in cases {
            let mut upload_attempts = 0;
            let mut exec_attempts = 0;
            let result = execute_after_staging(
                async {
                    match admit_run_local_cache(probe, 17, &digest, || async {
                        upload_attempts += 1;
                        Ok(17)
                    })
                    .await?
                    {
                        CacheAdmission::Match | CacheAdmission::UploadComplete(_) => Ok("program"),
                        CacheAdmission::Corrupt { .. } => {
                            Err(crate::invalid_config("corrupt cache".to_owned()))
                        }
                        CacheAdmission::UploadFailed(error) => Err(error),
                    }
                },
                |_program| async {
                    exec_attempts += 1;
                    Ok(())
                },
            )
            .await;

            assert_eq!(upload_attempts, expected_uploads, "{name}: upload attempts");
            assert_eq!(exec_attempts, expected_execs, "{name}: exec attempts");
            if name == "corrupt" {
                assert!(result.is_err(), "{name}: corrupt content is refused");
            } else if expected_execs == 0 {
                assert!(result.is_err(), "{name}: staging failure suppresses exec");
            } else {
                assert!(result.is_ok(), "{name}: verified content reaches exec");
            }
        }
    }

    #[test]
    fn run_local_timings_are_disabled_unless_value_is_one() {
        assert!(RunLocalTimings::from_env_value(None).is_none());
        assert!(RunLocalTimings::from_env_value(Some(std::ffi::OsStr::new("true"))).is_none());
        assert!(RunLocalTimings::from_env_value(Some(std::ffi::OsStr::new("0"))).is_none());
        let mut enabled = RunLocalTimings::from_env_value(Some(std::ffi::OsStr::new("1")));
        assert!(enabled.is_some());
        let enabled = enabled.as_mut().expect("timings enabled");
        enabled.record_cache_hit(17);
        enabled.record_cache_hit(23);
        enabled.record_completed_upload(17);
        enabled.record_completed_upload(23);
        assert_eq!(enabled.cache_hits, 2);
        assert_eq!(enabled.cache_reused_bytes, 40);
        assert_eq!(enabled.completed_uploads, 2);
        assert_eq!(enabled.uploaded_bytes, 40);
        assert!(
            RunLocalStage::new(None, super::RunLocalTimingStage::Exec)
                .started
                .is_none()
        );
        assert!(
            RunLocalStage::new(Some(enabled), super::RunLocalTimingStage::Exec)
                .started
                .is_some()
        );
    }

    #[test]
    fn run_local_output_forwarding_preserves_exact_bytes_once() {
        let child_stdout = [0, 0xff, b'\n', b't', b'e', b's', b't'];
        let child_stderr = [0xfe, b'w', b'a', b'r', b'n', b'\n'];
        let evidence_stdout = child_stdout.to_vec();
        let evidence_stderr = child_stderr.to_vec();
        let mut local_stdout = Vec::new();
        let mut local_stderr = Vec::new();

        forward_run_local_output(
            &child_stdout,
            &child_stderr,
            &mut local_stdout,
            &mut local_stderr,
        )
        .expect("child output forwards to local streams");

        assert_eq!(local_stdout, child_stdout);
        assert_eq!(local_stderr, child_stderr);
        assert_eq!(local_stdout, evidence_stdout);
        assert_eq!(local_stderr, evidence_stderr);
    }

    #[test]
    fn run_local_output_forwarding_reports_real_stream_write_failures() {
        let directory = tempfile::tempdir().expect("temporary output fixture");
        let path = directory.path().join("read-only-output");
        std::fs::write(&path, b"existing").expect("write output fixture");

        let mut local_stdout = std::fs::File::open(&path).expect("open read-only stdout");
        let mut local_stderr = Vec::new();
        let error = forward_run_local_output(
            b"child stdout",
            b"child stderr",
            &mut local_stdout,
            &mut local_stderr,
        )
        .expect_err("read-only stdout rejects forwarding");
        assert_eq!(error.0, "stdout");
        assert!(local_stderr.is_empty(), "stderr follows successful stdout");

        let mut local_stdout = Vec::new();
        let mut local_stderr = std::fs::File::open(path).expect("open read-only stderr");
        let error = forward_run_local_output(
            b"child stdout",
            b"child stderr",
            &mut local_stdout,
            &mut local_stderr,
        )
        .expect_err("read-only stderr rejects forwarding");
        assert_eq!(local_stdout, b"child stdout");
        assert_eq!(error.0, "stderr");
    }

    #[test]
    fn run_local_output_limit_applies_to_evidence_and_normal_runs() {
        let maximum = super::super::execution_evidence::MAX_RAW_OUTPUT_BYTES;
        assert!(validate_run_local_output_size(maximum, maximum, false).is_ok());
        assert!(validate_run_local_output_size(maximum, maximum, true).is_ok());

        let normal_error = validate_run_local_output_size(maximum + 1, 0, false)
            .expect_err("normal run output remains bounded");
        assert!(normal_error.to_string().contains("per-stream limit"));

        let evidence_error = validate_run_local_output_size(0, maximum + 1, true)
            .expect_err("evidence output retains its bound");
        assert!(
            evidence_error
                .to_string()
                .contains("per-stream evidence limit")
        );
    }

    #[test]
    fn staging_budget_scales_per_artifact_and_caps_excessive_inputs() {
        let one = StageBudget::for_artifact_sizes([22_976_512]).expect("one artifact budget");
        assert_eq!(one.artifact_count, 1);
        assert_eq!(one.total_bytes, 22_976_512);
        assert_eq!(one.allocated, RUN_LOCAL_ARTIFACT_STAGING_DEADLINE);

        let three_sizes = [22_976_512, 55_960_064, 28_182_528];
        let three = StageBudget::for_artifact_sizes(three_sizes).expect("three artifact budget");
        assert_eq!(three.artifact_count, 3);
        assert_eq!(three.total_bytes, 107_119_104);
        assert_eq!(three.allocated, Duration::from_secs(540));

        assert_eq!(
            staging_budget_for_artifact_count(
                usize::MAX as u64,
                RUN_LOCAL_ARTIFACT_STAGING_DEADLINE,
                MAX_RUN_LOCAL_STAGING_DEADLINE,
            ),
            MAX_RUN_LOCAL_STAGING_DEADLINE,
            "excessive artifact counts cannot extend the hard wall-clock cap"
        );
        let maximum_size = StageBudget::for_artifact_sizes([u64::MAX])
            .expect("one large artifact remains bounded by the per-upload ceiling");
        assert_eq!(maximum_size.total_bytes, u64::MAX);
        assert_eq!(maximum_size.allocated, RUN_LOCAL_ARTIFACT_STAGING_DEADLINE);
        assert!(
            StageBudget::for_artifact_sizes([u64::MAX, 1]).is_err(),
            "aggregate byte overflow fails closed"
        );
        assert!(StageBudget::for_artifact_sizes([]).is_err());
    }

    #[tokio::test]
    async fn three_slow_bounded_uploads_can_finish_after_one_file_window() {
        // Scale seconds to milliseconds: each 70-second model transfer is within its
        // 180-second per-file ceiling, while three serialize to 210 seconds overall.
        let simulated_total = staging_budget_for_artifact_count(
            3,
            Duration::from_millis(180),
            Duration::from_millis(540),
        );
        let per_upload = Duration::from_millis(180);
        let deadline = tokio::time::Instant::now() + simulated_total;
        let started = tokio::time::Instant::now();

        let result = tokio::time::timeout_at(deadline, async {
            for _ in 0..3 {
                tokio::time::timeout(per_upload, tokio::time::sleep(Duration::from_millis(70)))
                    .await
                    .expect("each simulated transfer stays within its own bound");
            }
        })
        .await;

        result.expect("the aggregate budget covers all three bounded transfers");
        assert!(
            started.elapsed() > per_upload,
            "combined transfer time exceeds the one-artifact window"
        );
    }

    #[tokio::test]
    async fn capped_staging_timeout_cancels_once_without_retry() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let cap = staging_budget_for_artifact_count(
            4,
            Duration::from_millis(180),
            Duration::from_millis(540),
        );
        let attempts = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicBool::new(false));
        let marker = DropFlag(Arc::clone(&dropped));
        let result = tokio::time::timeout(cap, async {
            attempts.fetch_add(1, Ordering::SeqCst);
            let _marker = marker;
            std::future::pending::<()>().await;
        })
        .await;

        assert!(result.is_err(), "the hard cap terminates excessive staging");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            dropped.load(Ordering::SeqCst),
            "timeout aborts the active stage"
        );
    }
}
