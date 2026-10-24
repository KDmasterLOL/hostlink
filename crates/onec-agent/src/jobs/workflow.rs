//! Persistent job start/status/log/cancel/worker workflows.

#![deny(clippy::missing_docs_in_private_items)]

use super::*;
use onec_agent_protocol::{NativeExecutionEffect, NativeInvocationIdentity, RunLocalJobIdentity};
use std::time::Duration;

pub(super) fn invocation_sha256(request: &JobRequestFile) -> io::Result<String> {
    let run_local = request.run_local.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native invocation requires run-local identity",
        )
    })?;
    let native_effect = request.native_effect.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "native invocation requires declared effect",
        )
    })?;
    NativeInvocationIdentity {
        program: &request.program,
        args: &request.args,
        cwd: request.cwd.as_deref(),
        env: &request.env,
        stdin: request.stdin.as_ref(),
        results: &request.results,
        run_local,
        native_effect,
        native_suite_policy_sha256: request.native_suite_policy_sha256.as_deref(),
    }
    .sha256()
    .map_err(io::Error::other)
}

/// Builds the immutable pre-spawn commitment, including the Agent-derived exact testcase filter.
pub(super) fn native_invocation_commitment(
    request: &JobRequestFile,
    invocation_sha256: String,
    native_effect: NativeExecutionEffect,
) -> NativeInvocationCommitment {
    NativeInvocationCommitment {
        version: 1,
        invocation_sha256,
        requested_exact_testcase: onec_agent_protocol::requested_exact_testcase(&request.args)
            .map(str::to_owned),
        native_effect,
        results: request.results.clone(),
    }
}

/// Admits a caller-presented suite policy only when it matches the independent Agent pin and
/// every launch field covered by that policy.
pub(crate) fn validate_native_suite_policy_admission(
    policy: Option<&onec_agent_protocol::NativeSuitePolicy>,
    pinned_policy_sha256: Option<&str>,
    program_sha256: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    effect: onec_agent_protocol::NativeExecutionEffect,
) -> io::Result<Option<String>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    let pinned = pinned_policy_sha256.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Agent has no independently pinned native suite policy",
        )
    })?;
    let policy_sha256 = policy
        .sha256()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if policy_sha256 != pinned
        || policy.runner_sha256 != program_sha256
        || policy.args != args
        || &policy.env != env
        || policy.effect != effect
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native suite policy does not match the Agent pin or exact launch fields",
        ));
    }
    Ok(Some(policy_sha256))
}

/// Recomputes the pinned suite policy from durable launch fields before worker execution.
fn validate_persisted_native_suite_policy(request: &JobRequestFile) -> io::Result<()> {
    match (
        request.native_suite_policy_sha256.as_deref(),
        request.native_suite_expected_tests.as_ref(),
        request.run_local.as_ref(),
        request.native_effect,
    ) {
        (None, None, _, _) => Ok(()),
        (Some(expected_digest), Some(expected_tests), Some(run_local), Some(effect)) => {
            let policy = onec_agent_protocol::NativeSuitePolicy {
                version: 1,
                runner_sha256: run_local.candidate_sha256().to_owned(),
                args: request.args.clone(),
                env: request.env.clone(),
                expected_tests: expected_tests.clone(),
                effect,
            };
            let observed_digest = policy
                .sha256()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if observed_digest != expected_digest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable native suite inventory differs from its independently pinned policy digest",
                ));
            }
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable native suite policy fields are incomplete",
        )),
    }
}

/// Creates durable job state and starts a detached worker using the safe child-environment policy.
pub fn start_job(
    jobs_root: &Path,
    environment_policy: &AgentEnvironmentPolicy,
    launch: JobLaunchRequest,
    secret_env: SecretEnvironment,
) -> io::Result<AgentJobInfo> {
    let JobLaunchRequest {
        program,
        args,
        cwd,
        env,
        stdin,
        results,
        run_local,
        native_effect,
        native_suite_policy_sha256,
        native_suite_expected_tests,
    } = launch;
    if program.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job program is empty",
        ));
    }
    environment_policy.validate_request_environment(
        &env,
        &secret_env,
        RequestedChildKind::DurableJob,
    )?;
    onec_agent_protocol::validate_result_specs(&results)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if (native_effect.is_some() || native_suite_policy_sha256.is_some())
        && (run_local.is_none() || !secret_env.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native invocation observation requires run-local ownership and no secret environment",
        ));
    }
    if native_suite_policy_sha256.is_some() != native_suite_expected_tests.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native suite policy digest and approved inventory must be present together",
        ));
    }
    ensure_private_directory(jobs_root)?;
    let _run_local_ownership = if let Some(identity) = &run_local {
        let ownership = lock_run_local_identity(jobs_root, identity.run_id())?;
        ensure_run_local_not_abandoned(jobs_root, identity.run_id())?;
        match status_by_run_id_unlocked(jobs_root, identity.run_id()) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "run-local identity already belongs to a durable job",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        validate_run_local_candidate(jobs_root, &program, cwd.as_deref(), &env, identity)?;
        Some(ownership)
    } else {
        None
    };
    let created_unix_ms = unix_ms();
    let job_id = format!(
        "job-{created_unix_ms}-{}-{}",
        std::process::id(),
        JOB_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let job_dir = jobs_root.join(&job_id);
    create_private_directory(&job_dir)?;
    let mut launch_request = JobRequestFile {
        version: JOB_SCHEMA_VERSION,
        program,
        args,
        cwd,
        env,
        stdin,
        results,
        run_local: run_local.clone(),
        invocation_sha256: None,
        native_effect,
        native_suite_policy_sha256,
        native_suite_expected_tests,
    };
    if let Some(effect) = native_effect {
        let digest = invocation_sha256(&launch_request)?;
        launch_request.invocation_sha256 = Some(digest.clone());
        write_new_json_file(
            &job_dir.join("native-invocation.json"),
            &native_invocation_commitment(&launch_request, digest, effect),
        )?;
    }
    write_new_json_file(&job_dir.join("request.json"), &launch_request)?;
    let queued = AgentJobInfo {
        job_id: job_id.clone(),
        state: AgentJobState::Queued,
        worker_pid: None,
        spawn_owner_pid: Some(std::process::id()),
        process_pid: None,
        exit_code: None,
        created_unix_ms,
        started_unix_ms: None,
        finished_unix_ms: None,
        message: None,
        stdout_log_truncated: false,
        stderr_log_truncated: false,
        result_set: None,
        run_local,
    };
    write_state(&job_dir, 0, &queued)?;

    let current = std::env::current_exe()?;
    let mut command = Command::new(current);
    environment_policy.apply_safe_base(&mut command);
    command
        .arg("__job-worker")
        .arg("--job-dir")
        .arg(&job_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !secret_env.is_empty() {
        let serialized = serde_json::to_string(&secret_env)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        command.env(INTERNAL_JOB_SECRET_ENV, serialized);
    }
    configure_detached_process(&mut command);
    let mut worker = match command.spawn() {
        Ok(worker) => worker,
        Err(error) => {
            let mut failed = queued.clone();
            failed.state = AgentJobState::Failed;
            failed.spawn_owner_pid = None;
            failed.finished_unix_ms = Some(unix_ms());
            failed.message = Some(format!("failed to start job worker: {error}"));
            let _ = write_state(&job_dir, 1, &failed);
            return Err(error);
        }
    };
    let queued = {
        let _control = acquire_job_control_lock(&job_dir)?;
        let mut latest = read_latest_state(&job_dir)?;
        if latest.state == AgentJobState::Queued {
            latest.worker_pid = Some(worker.id());
            latest.spawn_owner_pid = None;
            write_next_state(&job_dir, &latest)?;
        }
        latest
    };
    // Reap normally completed workers while this serving agent remains alive. If the serving
    // agent itself exits, the OS reparents the independent worker and the job continues.
    thread::spawn(move || {
        let _ = worker.wait();
    });
    Ok(queued)
}

/// Acquires the Agent-side ownership lock for one prepared run-local workspace.
pub(crate) fn lock_run_local_identity(jobs_root: &Path, run_id: &str) -> io::Result<fs::File> {
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid run-local identity",
        ));
    }
    let locks_root = jobs_root.join("run-local-locks");
    ensure_run_local_lock_directory(jobs_root)?;
    let lock_path = locks_root.join(format!("{run_id}.lock"));
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata)
            if metadata.is_file()
                && !crate::results::std_metadata_is_symlink_or_reparse(&metadata) => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "run-local ownership lock is not a regular file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    onec_core::acquire_exclusive_file_lock(
        lock_path,
        Duration::from_secs(60),
        Duration::from_millis(10),
    )
}

fn ensure_run_local_lock_directory(jobs_root: &Path) -> io::Result<()> {
    let locks_root = jobs_root.join("run-local-locks");
    for path in [jobs_root, locks_root.as_path()] {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.is_dir()
                    && !crate::results::std_metadata_is_symlink_or_reparse(&metadata) =>
            {
                onec_core::ensure_private_directory(path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "run-local ownership lock root is not an owned directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if path == jobs_root {
                    onec_core::ensure_private_directory(path)?;
                } else {
                    onec_core::create_private_directory(path)?;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Rejects reuse of a run ID after workspace abandonment.
pub(crate) fn ensure_run_local_not_abandoned(jobs_root: &Path, run_id: &str) -> io::Result<()> {
    let tombstones = jobs_root.join("run-local-abandoned");
    match fs::symlink_metadata(&tombstones) {
        Ok(metadata)
            if metadata.is_dir()
                && !crate::results::std_metadata_is_symlink_or_reparse(&metadata) =>
        {
            let marker = tombstones.join(run_id);
            match fs::symlink_metadata(marker) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "run-local identity was already abandoned",
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local abandonment root is not an owned directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Permanently records that an unstarted run-local identity was abandoned.
pub(crate) fn mark_run_local_abandoned(jobs_root: &Path, run_id: &str) -> io::Result<()> {
    let tombstones = jobs_root.join("run-local-abandoned");
    match fs::symlink_metadata(&tombstones) {
        Ok(metadata)
            if metadata.is_dir()
                && !crate::results::std_metadata_is_symlink_or_reparse(&metadata) =>
        {
            let marker = tombstones.join(run_id);
            match fs::symlink_metadata(&marker) {
                Ok(metadata)
                    if metadata.is_file()
                        && !crate::results::std_metadata_is_symlink_or_reparse(&metadata)
                        && fs::read(&marker)? == b"abandoned\n" =>
                {
                    return Ok(());
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "run-local abandonment marker is invalid",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "run-local abandonment root is not an owned directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_directory(&tombstones)?;
        }
        Err(error) => return Err(error),
    }
    write_new_private_bytes(&tombstones.join(run_id), b"abandoned\n")
}

pub(super) fn validate_run_local_candidate(
    jobs_root: &Path,
    program: &str,
    cwd: Option<&str>,
    env: &BTreeMap<String, String>,
    identity: &RunLocalJobIdentity,
) -> io::Result<()> {
    let run_parent = jobs_root.join("run-local-runs");
    let run_parent_metadata = fs::symlink_metadata(&run_parent)?;
    if !run_parent_metadata.is_dir()
        || crate::results::std_metadata_is_symlink_or_reparse(&run_parent_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run-local workspace parent is not an owned directory",
        ));
    }
    let run_root = jobs_root.join("run-local-runs").join(identity.run_id());
    let run_metadata = fs::symlink_metadata(&run_root)?;
    if !run_metadata.is_dir() || crate::results::std_metadata_is_symlink_or_reparse(&run_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "prepared run-local workspace is not an owned directory",
        ));
    }
    let cache_root = jobs_root.join("run-local-cache");
    let cache_metadata = fs::symlink_metadata(&cache_root)?;
    if !cache_metadata.is_dir()
        || crate::results::std_metadata_is_symlink_or_reparse(&cache_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "candidate cache is not an owned directory",
        ));
    }
    if cwd != Some(run_root.to_string_lossy().as_ref()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local-candidate working directory does not match its prepared workspace",
        ));
    }
    let candidate_path = jobs_root
        .join("run-local-cache")
        .join(identity.candidate_name());
    if program != candidate_path.to_string_lossy() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local candidate path does not match its content-addressed identity",
        ));
    }
    let candidate_meta = fs::symlink_metadata(&candidate_path)?;
    if !candidate_meta.is_file()
        || crate::results::std_metadata_is_symlink_or_reparse(&candidate_meta)
        || onec_core::sha256_file(&candidate_path)? != identity.candidate_sha256()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local candidate bytes do not match the declared digest",
        ));
    }
    ensure_run_local_candidate_executable(&candidate_path)?;
    let mapped_root = run_root.join("mapped");
    if !identity.mapped_files().is_empty() {
        let mapped_root_metadata = fs::symlink_metadata(&mapped_root)?;
        if !mapped_root_metadata.is_dir()
            || crate::results::std_metadata_is_symlink_or_reparse(&mapped_root_metadata)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mapped-input root is not an owned directory",
            ));
        }
    }
    for mapped in identity.mapped_files() {
        let path = run_root.join("mapped").join(format!(
            "{}-sha256-{}",
            mapped.environment_name(),
            mapped.sha256()
        ));
        if env.get(mapped.environment_name()) != Some(&path.to_string_lossy().into_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mapped-file environment path does not match its prepared workspace identity",
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || crate::results::std_metadata_is_symlink_or_reparse(&metadata)
            || onec_core::sha256_file(&path)? != mapped.sha256()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mapped-file bytes do not match the declared digest",
            ));
        }
    }
    Ok(())
}

/// Makes a verified Agent-owned local candidate executable on Unix without changing its bytes.
fn ensure_run_local_candidate_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let metadata = fs::symlink_metadata(path)?;
        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        if mode & 0o111 == 0 {
            permissions.set_mode(mode | 0o700);
            fs::set_permissions(path, permissions)?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Return the durable job IDs that still require the agent runtime to remain stable.
pub(crate) fn active_ids(jobs_root: &Path) -> io::Result<Vec<String>> {
    if !jobs_root.exists() {
        return Ok(Vec::new());
    }
    let mut active = Vec::new();
    for entry in fs::read_dir(jobs_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("job-"))
        {
            continue;
        }
        // Managed-update admission is intentionally observational. It must not create
        // a control lock or reconcile stale state while deciding whether an update may
        // proceed; a persisted non-terminal record is sufficient reason to defer.
        let current = read_latest_state(&entry.path())?;
        if !current.state.is_terminal() {
            active.push(current.job_id);
        }
    }
    active.sort();
    Ok(active)
}

/// Reconciles stale worker and pre-spawn states before the Agent begins serving control requests.
pub(crate) fn recover_stale_jobs(jobs_root: &Path) -> io::Result<()> {
    if !jobs_root.exists() {
        return Ok(());
    }
    let mut job_ids = Vec::new();
    for entry in fs::read_dir(jobs_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("job-"))
        {
            job_ids.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    job_ids.sort();
    for job_id in job_ids {
        match status(jobs_root, &job_id) {
            Ok(_) => {}
            // A live PID-only record can be either an old worker or PID reuse. Preserve it.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads the latest durable state for one exact validated job identifier.
pub fn status(jobs_root: &Path, job_id: &str) -> io::Result<AgentJobInfo> {
    let job_dir = job_dir(jobs_root, job_id)?;
    let _control = acquire_job_control_lock(&job_dir)?;
    status_unlocked(jobs_root, job_id)
}

fn status_unlocked(jobs_root: &Path, job_id: &str) -> io::Result<AgentJobInfo> {
    let job_dir = job_dir(jobs_root, job_id)?;
    let mut record = read_latest_state_file(&job_dir)?;
    if !record.job.state.is_terminal() && legacy_identity_is_ambiguous(&record) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "legacy durable job PID exists but its process identity cannot be verified",
        ));
    }
    let should_reconcile = should_reconcile_stale(&record);
    if !record.job.state.is_terminal() && should_reconcile {
        // Re-read once in case the worker published a terminal state between checks.
        let latest = read_latest_state_file(&job_dir)?;
        if latest.job.state.is_terminal() || !should_reconcile_stale(&latest) {
            record = latest;
        } else {
            record = latest;
            let legacy_owner = record_uses_legacy_identity(&record);
            let queued_without_worker = record.job.state == AgentJobState::Queued;
            if queued_without_worker {
                match fs::remove_file(job_dir.join("request.json")) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            record.job.state = if queued_without_worker {
                AgentJobState::Failed
            } else {
                AgentJobState::Interrupted
            };
            record.job.spawn_owner_pid = None;
            record.job.finished_unix_ms = Some(unix_ms());
            record.job.message = Some(if legacy_owner {
                "legacy job PID-only record reconciled after recorded processes were absent".into()
            } else if queued_without_worker {
                "job launch owner exited before a worker was started".into()
            } else {
                "job worker exited before publishing terminal state".into()
            });
            apply_log_truncation_flags(&job_dir, &mut record.job)?;
            write_next_state(&job_dir, &record.job)?;
            // Do not delete unpublished result workspace during interrupted recovery. The child
            // runs under the same OS identity and knows its incoming result path, so no marker in
            // this directory can prove descendant teardown independently of the child. Preserve
            // the workspace unless a future owner can re-establish OS-level tree authority.
            record = read_latest_state_file(&job_dir)?;
        }
    }
    apply_log_truncation_flags(&job_dir, &mut record.job)?;
    Ok(record.job)
}

pub(super) fn process_status(
    pid: Option<u32>,
    identity: Option<&ProcessIdentity>,
    identities_version: u32,
) -> ProcessStatus {
    match (pid, identity) {
        (None, _) => ProcessStatus::Dead,
        // Even without a persisted start token (historic state or a worker that exited
        // before capture), the complete absence of that PID proves the old worker is gone.
        // A live/reused PID with no token remains unverifiable and cannot be signaled.
        (Some(pid), None) => {
            if process_absent(pid) {
                ProcessStatus::Dead
            } else {
                ProcessStatus::Unverifiable
            }
        }
        (Some(pid), Some(identity)) if identities_version == 1 && identity.pid == pid => {
            identity.status()
        }
        (Some(_), Some(_)) => ProcessStatus::Unverifiable,
    }
}

fn should_reconcile_stale(record: &JobStateFile) -> bool {
    let worker = process_status(
        record.job.worker_pid,
        record.process_identities.worker.as_ref(),
        record.process_identities.version,
    );
    let spawn_owner = process_status(
        record.job.spawn_owner_pid,
        record.process_identities.spawn_owner.as_ref(),
        record.process_identities.version,
    );
    let worker_not_live = worker == ProcessStatus::Dead;
    let spawn_owner_not_live = spawn_owner == ProcessStatus::Dead;
    if record.job.state == AgentJobState::Queued {
        worker_not_live && spawn_owner_not_live
    } else {
        record.job.worker_pid.is_some() && worker_not_live
    }
}

fn record_uses_legacy_identity(record: &JobStateFile) -> bool {
    record.process_identities.version == 0
}

fn legacy_identity_is_ambiguous(record: &JobStateFile) -> bool {
    if record.process_identities.version != 0 {
        return false;
    }
    [record.job.worker_pid, record.job.spawn_owner_pid]
        .into_iter()
        .flatten()
        .any(|pid| !process_absent(pid))
}

/// Resolves durable run-local state by controller-generated workspace identity.
pub fn status_by_run_id(jobs_root: &Path, run_id: &str) -> io::Result<AgentJobInfo> {
    if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid run-local identity",
        ));
    }
    let _ownership = lock_run_local_identity(jobs_root, run_id)?;
    status_by_run_id_unlocked(jobs_root, run_id)
}

/// Looks up a run-local job while the caller already owns its run identity lock.
pub(crate) fn status_by_run_id_unlocked(
    jobs_root: &Path,
    run_id: &str,
) -> io::Result<AgentJobInfo> {
    for entry in fs::read_dir(jobs_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || !entry.file_name().to_string_lossy().starts_with("job-")
        {
            continue;
        }
        // The caller owns this run ID's identity lock. Read unrelated jobs observationally so
        // their control locks and stale-state reconciliation cannot delay this lookup. A matching
        // record is then re-read and reconciled under its authoritative job control lock.
        let persisted = read_latest_state(&entry.path())?;
        if persisted
            .run_local
            .as_ref()
            .is_some_and(|identity| identity.run_id() == run_id)
        {
            return match status(jobs_root, &entry.file_name().to_string_lossy()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "run-local identity already belongs to an unverifiable durable job",
                )),
                result => result,
            };
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "run-local job was not found",
    ))
}

/// Reads bounded stdout/stderr tails and durable truncation evidence for one job.
pub fn logs(jobs_root: &Path, job_id: &str, tail_bytes: u64) -> io::Result<JobLogTail> {
    let job_dir = job_dir(jobs_root, job_id)?;
    let tail_bytes = tail_bytes.min(MAX_LOG_TAIL_BYTES);
    let stdout = RetainedLog::new(job_dir.join("stdout.log"))?.read_tail(tail_bytes)?;
    let stderr = RetainedLog::new(job_dir.join("stderr.log"))?.read_tail(tail_bytes)?;
    Ok(JobLogTail {
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        stdout_storage_truncated: stdout.storage_truncated,
        stderr_storage_truncated: stderr.storage_truncated,
    })
}

/// Requests cancellation of one durable job and returns the resulting durable state.
pub fn cancel(jobs_root: &Path, job_id: &str) -> io::Result<AgentJobInfo> {
    let job_dir = job_dir(jobs_root, job_id)?;
    // Linearize cancellation-marker creation against the worker's terminal
    // commit. Once either side owns this lock, the other observes its durable
    // result before deciding whether cancellation can still be requested.
    let _control = acquire_job_control_lock(&job_dir)?;
    let current = status_unlocked(jobs_root, job_id)?;
    if current.state.is_terminal() {
        return Ok(current);
    }
    let marker = job_dir.join("cancel.request");
    if !marker.exists() {
        write_new_private_bytes(&marker, b"cancel\n")?;
    }
    Ok(current)
}

/// Runs the detached worker lifecycle for one already-created durable job directory.
pub async fn run_worker(job_dir: &Path) -> io::Result<()> {
    let secret_env = match std::env::var(INTERNAL_JOB_SECRET_ENV) {
        Ok(value) => serde_json::from_str::<SecretEnvironment>(&value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        Err(std::env::VarError::NotPresent) => SecretEnvironment::default(),
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
    };
    let _launch_control = acquire_job_control_lock(job_dir)?;
    let request: JobRequestFile =
        read_json_file_bounded(&job_dir.join("request.json"), JOB_REQUEST_MAX_BYTES)?;
    if request.version != JOB_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported job request version",
        ));
    }
    if validate_persisted_native_suite_policy(&request).is_err() {
        let mut current = read_latest_state(job_dir)?;
        if current.state.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "durable job was recovered terminal before worker startup",
            ));
        }
        current.state = AgentJobState::Failed;
        current.finished_unix_ms = Some(unix_ms());
        current.message =
            Some("durable native suite policy no longer matches its approved digest".to_owned());
        current.worker_pid = None;
        current.spawn_owner_pid = None;
        write_next_state(job_dir, &current)?;
        return Ok(());
    }
    let request_digest = request
        .native_effect
        .map(|_| invocation_sha256(&request))
        .transpose()?;
    if request.invocation_sha256 != request_digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable invocation differs from its immutable pre-spawn commitment",
        ));
    }
    match request.native_effect {
        Some(effect) => {
            let commitment_path = job_dir.join("native-invocation.json");
            let commitment_metadata = fs::symlink_metadata(&commitment_path)?;
            if !commitment_metadata.is_file()
                || crate::results::std_metadata_is_symlink_or_reparse(&commitment_metadata)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native invocation commitment is not a regular file",
                ));
            }
            let commitment: NativeInvocationCommitment =
                read_json_file_bounded(&commitment_path, 16 * 1024)?;
            if commitment.version != 1
                || commitment.invocation_sha256
                    != request.invocation_sha256.as_deref().unwrap_or_default()
                || commitment.requested_exact_testcase
                    != onec_agent_protocol::requested_exact_testcase(&request.args)
                        .map(str::to_owned)
                || commitment.native_effect != effect
                || commitment.results != request.results
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native invocation commitment differs from the persisted launch request",
                ));
            }
        }
        None if request.invocation_sha256.is_some() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unclassified launch request contains a native invocation commitment",
            ));
        }
        None => {}
    }
    let mut current = read_latest_state(job_dir)?;
    if current.state.is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "durable job was recovered terminal before worker startup",
        ));
    }
    current.worker_pid = Some(std::process::id());
    current.spawn_owner_pid = None;
    current.state = AgentJobState::Running;
    current.started_unix_ms = Some(unix_ms());
    write_next_state(job_dir, &current)?;
    // Publish worker ownership before deleting argv. If the worker dies after this point, a later
    // status can prove it vanished and transition the job to interrupted instead of leaving an
    // unowned queued record forever. The raw launch request is removed immediately afterward.
    fs::remove_file(job_dir.join("request.json"))?;
    drop(_launch_control);

    let patterns = secret_patterns(&secret_env);
    let environment_policy = AgentEnvironmentPolicy::detached_worker();
    let cancel_token = processkit::CancellationToken::new();
    let mut command = processkit::Command::new(&request.program)
        .args(&request.args)
        .create_no_window()
        .fail_on_stdin_broken_pipe()
        .cancel_on(cancel_token.clone());

    if let Some(identity) = &request.run_local {
        validate_run_local_candidate(
            job_dir.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "job directory has no owner root",
                )
            })?,
            &request.program,
            request.cwd.as_deref(),
            &request.env,
            identity,
        )?;
    }

    command = environment_policy.prepare_processkit_command(
        command,
        &request.env,
        &secret_env,
        RequestedChildKind::DurableJob,
    )?;
    if let Some(cwd) = &request.cwd {
        command = command.current_dir(cwd);
    }
    if let Some(stdin) = &request.stdin {
        command = command.stdin(processkit::Stdin::from_bytes(stdin.as_bytes().to_vec()));
    } else {
        command = command.stdin(processkit::Stdin::empty());
    }

    let mut result_workspace = match crate::results::ResultWorkspace::prepare_job(
        job_dir,
        &current.job_id,
        &request.results,
    ) {
        Ok(workspace) => workspace,
        Err(error) => {
            current.state = AgentJobState::Failed;
            current.finished_unix_ms = Some(unix_ms());
            current.message = Some(format!("failed to prepare result artifacts: {error}"));
            publish_prelaunch_terminal(job_dir, &mut current)?;
            return Ok(());
        }
    };
    if let Some(workspace) = &result_workspace {
        command = command.env(onec_core::ONEC_RESULT_DIR_ENV, workspace.incoming_path());
    }

    // Durable job identity is agent-owned. Apply it after both request environment layers so the
    // child cannot observe a guessed or spoofed job ID.
    command = command
        .env(ONEC_JOB_SYSTEM_ENV, ONEC_AGENT_JOB_SYSTEM)
        .env(ONEC_JOB_ID_ENV, &current.job_id);

    let stdout_path = job_dir.join("stdout.log");
    let stdout_patterns = patterns.clone();
    command = command.stdout_raw_sink(move || {
        ProcesskitDurableJobLogSink::new(stdout_path.clone(), stdout_patterns.clone())
    });
    let stderr_path = job_dir.join("stderr.log");
    command = command.stderr_raw_sink(move || {
        ProcesskitDurableJobLogSink::new(stderr_path.clone(), patterns.clone())
    });

    let mut child = match command.start().await {
        Ok(child) => child,
        Err(error) => {
            let primary = format!("failed to start process: {error}");
            current.state = AgentJobState::Failed;
            current.finished_unix_ms = Some(unix_ms());
            current.message = Some(discard_result_workspace_with_primary(
                &mut result_workspace,
                primary,
            ));
            publish_prelaunch_terminal(job_dir, &mut current)?;
            return Ok(());
        }
    };

    current.process_pid = child.pid();
    if let Err(error) = write_next_state(job_dir, &current) {
        cancel_token.cancel();
        let teardown = child.wait().await;
        if processkit_teardown_confirmed(&teardown)
            && let Err(cleanup) = try_discard_result_workspace(&mut result_workspace)
        {
            return Err(io::Error::other(format!(
                "failed to publish running job state: {error}; additionally failed to discard result workspace: {cleanup}"
            )));
        }
        return Err(error);
    }

    enum RequestedStop {
        Cancellation,
        ResultPolicy(String),
    }

    let mut requested_stop = None;
    let completion = loop {
        match child.wait_for_tree_exit(Duration::from_millis(200)).await {
            Ok(()) => break child.wait().await,
            Err(error) if matches!(error.reason(), processkit::ErrorReason::NotReady { .. }) => {
                if requested_stop.is_some() {
                    continue;
                }
                if job_dir.join("cancel.request").exists() {
                    requested_stop = Some(RequestedStop::Cancellation);
                    cancel_token.cancel();
                    continue;
                }
                if let Some(workspace) = &result_workspace
                    && let Err(error) = workspace.supervise()
                {
                    requested_stop = Some(RequestedStop::ResultPolicy(format!(
                        "result artifact policy violation: {error}"
                    )));
                    cancel_token.cancel();
                }
            }
            Err(error) => {
                cancel_token.cancel();
                let teardown = child.wait().await;
                let primary = processkit_worker_error(error);
                if processkit_teardown_confirmed(&teardown)
                    && let Err(cleanup) = try_discard_result_workspace(&mut result_workspace)
                {
                    return Err(io::Error::other(format!(
                        "{primary}; additionally failed to discard result workspace: {cleanup}"
                    )));
                }
                return Err(primary);
            }
        }
    };

    // ProcessKit can fail with an I/O or sink error without proving that the
    // process tree is gone. Do not turn that uncertainty into recursive cleanup.
    if !processkit_teardown_confirmed(&completion) {
        let error = completion
            .as_ref()
            .expect_err("unconfirmed completion must be an error");
        return Err(io::Error::other(format!(
            "job process completion failed: {error}; process-tree teardown was not confirmed; incoming result workspace retained"
        )));
    }

    // Serialize the final cancellation decision with cancel(). A marker created
    // before this lock was acquired wins; a concurrent cancel that arrives after
    // this point blocks until the terminal state is durable and then observes it.
    let _control = acquire_job_control_lock(job_dir)?;
    if requested_stop.is_none() && job_dir.join("cancel.request").exists() {
        requested_stop = Some(RequestedStop::Cancellation);
    }

    match requested_stop {
        Some(RequestedStop::Cancellation) => {
            match completion {
                Ok(outcome) => current.exit_code = outcome.code(),
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    if let Some(message) = raw_sink_failure_message(&error) {
                        current.state = AgentJobState::Failed;
                        current.finished_unix_ms = Some(unix_ms());
                        current.message = Some(discard_result_workspace_with_primary(
                            &mut result_workspace,
                            message,
                        ));
                    } else {
                        return Err(processkit_worker_error(error));
                    }
                }
            }
            if current.state != AgentJobState::Failed {
                current.state = AgentJobState::Canceled;
                current.finished_unix_ms = Some(unix_ms());
                current.message = Some(discard_result_workspace_with_primary(
                    &mut result_workspace,
                    "cancellation requested".into(),
                ));
            }
        }
        Some(RequestedStop::ResultPolicy(message)) => {
            match completion {
                Ok(_) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    if let Some(log_message) = raw_sink_failure_message(&error) {
                        current.state = AgentJobState::Failed;
                        current.finished_unix_ms = Some(unix_ms());
                        current.message = Some(discard_result_workspace_with_primary(
                            &mut result_workspace,
                            log_message,
                        ));
                    } else {
                        return Err(processkit_worker_error(error));
                    }
                }
            }
            if current.state != AgentJobState::Failed {
                current.state = AgentJobState::Failed;
                current.finished_unix_ms = Some(unix_ms());
                current.message = Some(discard_result_workspace_with_primary(
                    &mut result_workspace,
                    message,
                ));
            }
        }
        None => match completion {
            Ok(outcome) => {
                current.exit_code = outcome.code();
                current.finished_unix_ms = Some(unix_ms());
                if outcome.code() == Some(0) {
                    // Recheck the content-addressed executable after its complete process tree
                    // exits. A successful process result must not survive candidate replacement
                    // while it was running.
                    let candidate_check = if let Some(identity) = &request.run_local {
                        let jobs_root = job_dir.parent().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "job directory has no owner root",
                            )
                        })?;
                        validate_run_local_candidate(
                            jobs_root,
                            &request.program,
                            request.cwd.as_deref(),
                            &request.env,
                            identity,
                        )
                    } else {
                        Ok(())
                    };
                    if let Err(error) = candidate_check {
                        current.state = AgentJobState::Failed;
                        current.message = Some(discard_result_workspace_with_primary(
                            &mut result_workspace,
                            format!(
                                "run-local executable or mapped input changed during execution: {error}"
                            ),
                        ));
                    } else {
                        current.state = AgentJobState::Succeeded;
                        if let Some(workspace) = &result_workspace {
                            match workspace.finalize() {
                                Ok(result_set) => current.result_set = Some(result_set),
                                Err(error) => {
                                    current.state = AgentJobState::Failed;
                                    current.message = Some(discard_result_workspace_with_primary(
                                        &mut result_workspace,
                                        format!("failed to publish result artifacts: {error}"),
                                    ));
                                }
                            }
                        }
                    }
                } else {
                    current.state = AgentJobState::Failed;
                }
            }
            Err(error) => match error.reason() {
                processkit::ErrorReason::Stdin { .. } => {
                    current.exit_code = error.code();
                    current.state = AgentJobState::Failed;
                    current.finished_unix_ms = Some(unix_ms());
                    current.message = Some(discard_result_workspace_with_primary(
                        &mut result_workspace,
                        format!("failed to write job stdin: {error}"),
                    ));
                }
                processkit::ErrorReason::RawSink { stream, source } => {
                    current.state = AgentJobState::Failed;
                    current.finished_unix_ms = Some(unix_ms());
                    current.message = Some(discard_result_workspace_with_primary(
                        &mut result_workspace,
                        format!("failed to persist durable {stream:?} log: {source}"),
                    ));
                }
                _ => {
                    let primary = processkit_worker_error(error);
                    return match try_discard_result_workspace(&mut result_workspace) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(io::Error::other(format!(
                            "{primary}; additionally failed to discard result workspace: {cleanup}"
                        ))),
                    };
                }
            },
        },
    }

    apply_log_truncation_flags(job_dir, &mut current)?;
    if current.state == AgentJobState::Succeeded
        && current.run_local.is_some()
        && request.native_effect.is_some()
    {
        let commit = job_dir
            .parent()
            .ok_or_else(|| io::Error::other("job directory has no owner root"))
            .and_then(|jobs_root| {
                let logs = crate::native_attestation::read_complete_invocation_output_logs(
                    jobs_root,
                    &current.job_id,
                    &current,
                )?;
                let invocation_sha256 = request.invocation_sha256.as_deref().ok_or_else(|| {
                    io::Error::other("native invocation digest is missing from the worker request")
                })?;
                crate::native_attestation::write_completed_invocation_output_logs(
                    jobs_root,
                    &current,
                    invocation_sha256,
                    logs,
                    current.result_set.clone(),
                )
            });
        if let Err(error) = commit {
            current.state = AgentJobState::Failed;
            current.message = Some(format!(
                "failed to commit complete Agent-owned output logs: {error}"
            ));
        }
    }
    write_next_state(job_dir, &current)?;
    Ok(())
}

fn processkit_worker_error(error: processkit::Error) -> io::Error {
    match error.into_reason() {
        processkit::ErrorReason::RawSink { stream, source } => io::Error::new(
            source.kind(),
            format!("failed to persist durable {stream:?} log: {source}"),
        ),
        reason => io::Error::other(format!("job process lifecycle failed: {reason}")),
    }
}

fn raw_sink_failure_message(error: &processkit::Error) -> Option<String> {
    match error.reason() {
        processkit::ErrorReason::RawSink { stream, source } => Some(format!(
            "failed to persist durable {stream:?} log: {source}"
        )),
        _ => None,
    }
}

fn processkit_teardown_confirmed(result: &processkit::Result<processkit::Outcome>) -> bool {
    match result {
        Ok(_) => true,
        // ProcessKit's wait() reports Stdin/RawSink only after completing
        // process-tree teardown; generic Io/Teardown errors remain ambiguous.
        Err(error) => {
            error.is_cancelled()
                || matches!(
                    error.reason(),
                    processkit::ErrorReason::Stdin { .. } | processkit::ErrorReason::RawSink { .. }
                )
        }
    }
}

fn publish_prelaunch_terminal(job_dir: &Path, current: &mut AgentJobInfo) -> io::Result<()> {
    let _control = acquire_job_control_lock(job_dir)?;
    if job_dir.join("cancel.request").exists() {
        current.state = AgentJobState::Canceled;
        current.message = Some("cancellation requested".into());
    }
    write_next_state(job_dir, current)
}

fn try_discard_result_workspace(
    workspace: &mut Option<crate::results::ResultWorkspace>,
) -> io::Result<()> {
    if let Some(workspace) = workspace.take() {
        workspace.discard()?;
    }
    Ok(())
}

fn discard_result_workspace_with_primary(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    primary: String,
) -> String {
    discard_result_workspace_with_primary_and(
        workspace,
        primary,
        crate::results::ResultWorkspace::discard,
    )
}

pub(super) fn discard_result_workspace_with_primary_and(
    workspace: &mut Option<crate::results::ResultWorkspace>,
    primary: String,
    discard: impl FnOnce(crate::results::ResultWorkspace) -> io::Result<bool>,
) -> String {
    let cleanup = match workspace.take() {
        Some(workspace) => discard(workspace).map(|_| ()),
        None => Ok(()),
    };
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => {
            format!("{primary}; additionally failed to discard result workspace: {cleanup}")
        }
    }
}

#[cfg(test)]
mod suite_policy_tests {
    use super::*;

    fn policy() -> onec_agent_protocol::NativeSuitePolicy {
        onec_agent_protocol::NativeSuitePolicy {
            version: 1,
            runner_sha256: "a".repeat(64),
            args: vec!["run".into(), "--workspace".into()],
            env: BTreeMap::new(),
            expected_tests: vec!["crate::case_a".into(), "crate::case_b".into()],
            effect: onec_agent_protocol::NativeExecutionEffect::ReadOnly,
        }
    }

    #[test]
    fn agent_admits_only_the_exact_pinned_runner_argv_and_effect() {
        let policy = policy();
        let pin = policy.sha256().expect("policy digest");
        assert_eq!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&pin),
                &"a".repeat(64),
                &policy.args,
                &policy.env,
                policy.effect,
            )
            .expect("admit exact policy"),
            Some(pin.clone())
        );

        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                None,
                &"a".repeat(64),
                &policy.args,
                &policy.env,
                policy.effect,
            )
            .is_err()
        );
        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&"b".repeat(64)),
                &"a".repeat(64),
                &policy.args,
                &policy.env,
                policy.effect,
            )
            .is_err()
        );
        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&pin),
                &"b".repeat(64),
                &policy.args,
                &policy.env,
                policy.effect,
            )
            .is_err()
        );
        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&pin),
                &"a".repeat(64),
                &["run".into(), "--list".into()],
                &policy.env,
                policy.effect,
            )
            .is_err()
        );
        let mut changed_env = policy.env.clone();
        changed_env.insert("NEXTTEST_FILTER".into(), "case".into());
        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&pin),
                &"a".repeat(64),
                &policy.args,
                &changed_env,
                policy.effect,
            )
            .is_err()
        );
        assert!(
            validate_native_suite_policy_admission(
                Some(&policy),
                Some(&pin),
                &"a".repeat(64),
                &policy.args,
                &policy.env,
                onec_agent_protocol::NativeExecutionEffect::Disposable,
            )
            .is_err()
        );
    }
}
