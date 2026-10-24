//! Controller orchestration for reconnectable source-exact local-candidate jobs.

use super::mutable_lease;
use super::*;
use onec_agent_protocol::{
    AgentJobInfo, AgentJobState, AgentResponseKind, NativeInvocationIdentity, NativeSuitePolicy,
    RunLocalJobIdentity, RunLocalMappedFile,
};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

pub(super) struct StartOptions {
    pub(super) target: Option<String>,
    pub(super) effect: ManagedTargetEffect,
    pub(super) native_effect: Option<onec_agent_protocol::NativeExecutionEffect>,
    pub(super) native_suite_policy: Option<PathBuf>,
    pub(super) cwd: Option<String>,
    pub(super) ordinary_env: Vec<String>,
    pub(super) secret_bindings: Vec<String>,
    pub(super) mapped_env: Vec<String>,
    pub(super) result_args: Vec<String>,
    pub(super) require_cached_candidate: bool,
}

const MAX_NATIVE_SUITE_POLICY_BYTES: u64 = 1024 * 1024;

fn read_native_suite_policy(path: &Path) -> AppResult<NativeSuitePolicy> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        crate::invalid_config(format!(
            "cannot inspect native suite policy {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(crate::invalid_config(format!(
            "native suite policy {} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_NATIVE_SUITE_POLICY_BYTES {
        return Err(crate::invalid_config(format!(
            "native suite policy {} exceeds the 1 MiB size limit",
            path.display()
        )));
    }

    let file = std::fs::File::open(path).map_err(|error| {
        crate::invalid_config(format!(
            "cannot read native suite policy {}: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_NATIVE_SUITE_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            crate::invalid_config(format!(
                "cannot read native suite policy {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > MAX_NATIVE_SUITE_POLICY_BYTES {
        return Err(crate::invalid_config(format!(
            "native suite policy {} exceeds the 1 MiB size limit",
            path.display()
        )));
    }
    serde_json::from_slice::<NativeSuitePolicy>(&bytes).map_err(|error| {
        crate::invalid_config(format!("invalid native suite policy JSON: {error}"))
    })
}

pub(super) async fn start(
    options: StartOptions,
    command: Vec<String>,
) -> AppResult<(String, AgentJobInfo)> {
    let StartOptions {
        target,
        effect,
        native_effect,
        native_suite_policy,
        cwd,
        ordinary_env,
        secret_bindings,
        mapped_env,
        result_args,
        require_cached_candidate,
    } = options;
    validate_cache_only_options(require_cached_candidate, &mapped_env)?;
    let native_suite_policy = native_suite_policy
        .as_deref()
        .map(read_native_suite_policy)
        .transpose()?;
    if native_suite_policy.is_some() && native_effect.is_none() {
        return Err(crate::invalid_config(
            "--native-suite-policy requires explicit --native-effect".to_owned(),
        ));
    }
    if effect == ManagedTargetEffect::ReadOnly {
        return Err(crate::invalid_config("durable run-local jobs require run-owned or disposable effect so their cross-process reservation has an explicit mutable scope".to_owned()));
    }
    let target = target
        .or_else(|| std::env::var("ONEC_ACCESS_TARGET").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            crate::invalid_config(
                "run-local-job start requires --target or ONEC_ACCESS_TARGET".to_owned(),
            )
        })?;
    let (executable, args) = command.split_first().ok_or_else(|| {
        crate::invalid_config("run-local-job start requires a local executable".to_owned())
    })?;
    let executable = super::transport::local_regular_file(PathBuf::from(executable)).await?;
    let mut env = super::jobs::parse_env(&ordinary_env)?;
    let secret_env = super::secrets::resolve_secret_env(&secret_bindings, &env)?;
    if native_effect.is_some() && !secret_env.is_empty() {
        return Err(crate::invalid_config(
            "Agent-native invocation observation does not accept secret environment values"
                .to_owned(),
        ));
    }
    let results = super::jobs::parse_result_specs(&result_args)?;
    let has_mapped_env = !mapped_env.is_empty();
    let mut names = std::collections::HashSet::new();
    let mut mapped = Vec::new();
    for name in mapped_env {
        super::secrets::validate_environment_name(&name)?;
        if !names.insert(name.to_ascii_uppercase())
            || env.keys().any(|key| key.eq_ignore_ascii_case(&name))
            || secret_env.keys().any(|key| key.eq_ignore_ascii_case(&name))
        {
            return Err(crate::invalid_config(format!(
                "mapped environment name {name:?} is duplicated or conflicts with another environment option"
            )));
        }
        let source = std::env::var_os(&name).ok_or_else(|| {
            crate::invalid_config(format!(
                "mapped source environment variable {name:?} is not set"
            ))
        })?;
        mapped.push((
            name,
            super::transport::local_regular_file(PathBuf::from(source)).await?,
        ));
    }
    let candidate_identity =
        hostlink_core::FileDigest::from_path(&executable).map_err(|source| {
            crate::invalid_config(format!("cannot hash local executable: {source}"))
        })?;
    let candidate_digest = candidate_identity.sha256().to_owned();
    if let Some(policy) = &native_suite_policy {
        policy.sha256().map_err(|error| {
            crate::invalid_config(format!("invalid native suite policy: {error}"))
        })?;
        if has_mapped_env
            || policy.runner_sha256 != candidate_identity.sha256()
            || policy.args != args
            || policy.env != env
            || Some(policy.effect) != native_effect
            || !results.is_empty()
        {
            return Err(crate::invalid_config(
                "native suite policy must match the exact candidate, argv, environment, effect, and result-free launch"
                    .to_owned(),
            ));
        }
    }
    let candidate_name = super::transport::content_cache_name(&executable, &candidate_digest);
    let mut mapped_identities = Vec::new();
    let mut mapped_files = Vec::new();
    for (name, path) in mapped {
        let identity = hostlink_core::FileDigest::from_path(&path).map_err(|source| {
            crate::invalid_config(format!("cannot hash mapped file: {source}"))
        })?;
        let digest = identity.sha256().to_owned();
        mapped_identities.push((name.clone(), path, identity));
        mapped_files
            .push(RunLocalMappedFile::try_new(name, digest).map_err(crate::invalid_config)?);
    }
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let (machine_id, _hub, client) = resolve(&target).await?;
    if let Some(native_effect) = native_effect {
        if native_effect == onec_agent_protocol::NativeExecutionEffect::ReadOnly {
            return Err(crate::invalid_config(
                "durable run-local jobs do not support read-only effect authorization".to_owned(),
            ));
        }
        if native_suite_policy.is_some() {
            // Old Agents ignore unknown policy fields, so admission support must be proven before
            // reserving durable state or preparing/uploading any remote files.
            client
                .require_capability("native-suite-policy-admission-v1")
                .await?;
        }
        client
            .require_capability("native-invocation-observation-v1")
            .await?;
    }
    // This explicit capability preflight happens before run preparation and before every upload.
    client.require_local_candidate_job_support().await?;
    let data_root = controller_data_root()?;
    mutable_lease::reserve_durable_run_local(&data_root, &machine_id, &run_id)?;
    eprintln!("run_id={run_id}");
    std::io::stderr().flush().map_err(|error| {
        crate::invalid_config(format!(
            "failed to publish durable run-local identity: {error}"
        ))
    })?;
    let paths = client.prepare_run_local_job(run_id.clone()).await?;
    if cwd.as_deref().is_some_and(|cwd| cwd != paths.run_root) {
        let error = crate::invalid_config(
            "durable run-local jobs must use their prepared, job-owned run workspace as cwd"
                .to_owned(),
        );
        if require_cached_candidate {
            return abandon_unsubmitted_cache_only_run(
                &client,
                &data_root,
                &machine_id,
                &run_id,
                error,
            )
            .await;
        }
        return Err(error.context(format!(
            "durable run-local job {run_id} remains reserved for recovery"
        )));
    }
    let candidate_remote = super::transport::join_remote_path(&paths.cache_root, &candidate_name);
    let stage_budget = super::transport::StageBudget::for_artifact_sizes(
        std::iter::once(candidate_identity.bytes()).chain(
            mapped_identities
                .iter()
                .map(|(_, _, identity)| identity.bytes()),
        ),
    )?;
    let staging_deadline = stage_budget.deadline();
    let mut job_submission_attempted = false;
    if require_cached_candidate {
        let cache_probe = tokio::time::timeout_at(staging_deadline, async {
            super::transport::require_cached_candidate(
                &client,
                &candidate_remote,
                &candidate_identity,
                "cache_admission",
            )
            .await
        })
        .await;
        let cache_probe = match cache_probe {
            Ok(result) => result,
            Err(_) => Err(crate::invalid_config(
                "required cached run-local candidate check timed out; no upload was attempted"
                    .to_owned(),
            )),
        };
        if let Err(error) = cache_probe {
            return abandon_unsubmitted_cache_only_run(
                &client,
                &data_root,
                &machine_id,
                &run_id,
                error,
            )
            .await;
        }
    }
    let operation = async {
        tokio::time::timeout_at(staging_deadline, async {
            if !require_cached_candidate {
                super::transport::publish_or_reuse(
                    &client,
                    &executable,
                    &candidate_remote,
                    &candidate_identity,
                )
                .await?;
            }
            for (name, local, identity) in &mapped_identities {
                let directory = super::transport::join_remote_path(&paths.run_root, "mapped");
                let filename = format!("{name}-sha256-{}", identity.sha256());
                let remote = super::transport::join_remote_path(&directory, &filename);
                super::transport::publish_or_reuse(&client, local, &remote, identity).await?;
                env.insert(name.clone(), remote);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
            .map_err(|_| {
                crate::invalid_config(
                    "durable run-local staging deadline exceeded before start_job; remote state is reserved for recovery"
                        .to_owned(),
                )
            })??;
        let identity = RunLocalJobIdentity::try_new(
            run_id.clone(),
            candidate_name.clone(),
            candidate_digest.clone(),
            mapped_files,
        )
        .map_err(crate::invalid_config)?;
        let run_cwd = cwd.unwrap_or_else(|| paths.run_root.clone());
        if require_cached_candidate {
            tokio::time::timeout_at(staging_deadline, async {
                super::transport::require_cached_candidate(
                    &client,
                    &candidate_remote,
                    &candidate_identity,
                    "pre_submission",
                )
                .await
            })
            .await
            .map_err(|_| {
                crate::invalid_config(
                    "required cached run-local candidate recheck timed out; no upload was attempted"
                        .to_owned(),
                )
            })??;
        }
        if let Some(native_effect) = native_effect {
            let native_suite_policy_sha256 = native_suite_policy
                .as_ref()
                .map(NativeSuitePolicy::sha256)
                .transpose()
                .map_err(|source| {
                    crate::invalid_config(format!(
                        "cannot compute native suite policy SHA-256: {source}"
                    ))
                })?;
            let invocation_sha256 = NativeInvocationIdentity {
                program: &candidate_remote,
                args,
                cwd: Some(&run_cwd),
                env: &env,
                stdin: None,
                results: &results,
                run_local: &identity,
                native_effect,
                native_suite_policy_sha256: native_suite_policy_sha256.as_deref(),
            }
            .sha256()
            .map_err(|source| {
                crate::invalid_config(format!(
                    "cannot compute canonical Agent invocation SHA-256: {source}"
                ))
            })?;
            mutable_lease::persist_durable_native_invocation(
                &data_root,
                &machine_id,
                &run_id,
                &candidate_digest,
                &invocation_sha256,
                native_effect,
            )?;
            let start = client
                .start_native_run_local_job(candidate_remote)
                .args(args.to_vec())
                .cwd(run_cwd)
                .env(env)
                .results(results)
                .run_local(identity);
            job_submission_attempted = true;
            if let Some(suite_policy) = native_suite_policy {
                start.native_suite_policy(suite_policy)
                    .native_effect(native_effect)
                    .call()
                    .await
            } else {
                start.native_effect(native_effect).call().await
            }
        } else {
            job_submission_attempted = true;
            client
                .start_job(candidate_remote)
                .args(args.to_vec())
                .cwd(run_cwd)
                .env(env)
                .secret_env(secret_env)
                .results(results)
                .run_local(identity)
                .call()
                .await
        }
    }
    .await;
    let response = match operation {
        Ok(response) => response,
        Err(error) => {
            if require_cached_candidate && !job_submission_attempted {
                return abandon_unsubmitted_cache_only_run(
                    &client,
                    &data_root,
                    &machine_id,
                    &run_id,
                    error,
                )
                .await;
            }
            return Err(error.context(format!(
                "durable run-local job {run_id} remains reserved for recovery"
            )));
        }
    };
    let AgentResponseKind::JobStarted { job } = response else {
        return Err(crate::invalid_config(format!(
            "agent returned an unexpected durable job response; run {run_id} remains reserved"
        )));
    };
    ensure_run_local_job(&job, &run_id)?;
    if let Err(error) =
        mutable_lease::bind_durable_run_local_job(&data_root, &machine_id, &run_id, &job.job_id)
    {
        return Err(error.context(format!(
            "Agent job {} started but its controller reservation remains pending as run {run_id}",
            job.job_id
        )));
    }
    mutable_lease::verify_durable_run_local_job(&data_root, &machine_id, &run_id, &job.job_id)?;
    Ok((run_id, job))
}

fn validate_cache_only_options(
    require_cached_candidate: bool,
    mapped_env: &[String],
) -> AppResult<()> {
    if require_cached_candidate && !mapped_env.is_empty() {
        return Err(crate::invalid_config(
            "--require-cached-candidate cannot be combined with --map-file-env".to_owned(),
        ));
    }
    Ok(())
}

async fn abandon_unsubmitted_cache_only_run<T>(
    client: &RemoteAgentClient,
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
    cause: anyhow::Error,
) -> AppResult<T> {
    if let Err(cleanup) = client.abandon_run_local(run_id.to_owned()).await {
        return Err(cause.context(format!(
            "cache-only job was never submitted; run {run_id} remains reserved because prepared workspace cleanup failed: {cleanup:#}"
        )));
    }
    if let Err(cleanup) = mutable_lease::release_abandoned_run_local(data_root, machine_id, run_id)
    {
        return Err(cause.context(format!(
            "prepared cache-only workspace was abandoned, but reservation release failed for run {run_id}: {cleanup:#}"
        )));
    }
    Err(cause.context(format!(
        "cache-only job was never submitted; prepared run-local workspace was abandoned and reservation released for run {run_id}"
    )))
}

pub(super) async fn resolve(target: &str) -> AppResult<(String, HubClient, RemoteAgentClient)> {
    let (machine_id, hub) = resolve_machine_id_with_hub(target).await?;
    let client = RemoteAgentClient::new(hub.resolve_remote_server_for_machine(&machine_id).await?)?;
    Ok((machine_id, hub, client))
}

pub(super) async fn resolve_machine_id(target: &str) -> AppResult<String> {
    resolve_machine_id_with_hub(target)
        .await
        .map(|(machine_id, _)| machine_id)
}

async fn resolve_machine_id_with_hub(target: &str) -> AppResult<(String, HubClient)> {
    let config_path = hub_config_path()?;
    let hub = HubClient::configured()?.ok_or_else(|| {
        crate::not_found_error(format!(
            "hostlink config {}; configure access before using remote operations",
            config_path.display()
        ))
    })?;
    let agent = hub
        .resolve_agent(target)
        .await?
        .ok_or_else(|| crate::not_found_error(format!("hub-managed host {target:?}")))?;
    Ok((agent.machine_id, hub))
}

pub(super) async fn status_by_run(
    client: &RemoteAgentClient,
    data_root: &Path,
    machine_id: &str,
    run_id: &str,
) -> AppResult<AgentJobInfo> {
    match client.run_local_status(run_id.to_owned()).await? {
        AgentResponseKind::JobStatus { job } => {
            ensure_run_local_job(&job, run_id)?;
            mutable_lease::verify_durable_run_local_job(
                data_root,
                machine_id,
                run_id,
                &job.job_id,
            )?;
            Ok(job)
        }
        _ => Err(crate::invalid_config(
            "agent returned an unexpected run-local status response".to_owned(),
        )),
    }
}

pub(super) fn ensure_run_local_job(job: &AgentJobInfo, run_id: &str) -> AppResult<()> {
    if !job
        .run_local
        .as_ref()
        .is_some_and(|identity| identity.run_id() == run_id)
    {
        return Err(crate::invalid_config(
            "agent job does not match the requested run-local identity".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn controller_data_root() -> AppResult<PathBuf> {
    directories::ProjectDirs::from("", "", "onec-access")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or_else(|| {
            crate::invalid_config(
                "cannot determine OS-native application directories for hostlink".to_owned(),
            )
        })
}

pub(super) fn print_job(job: &AgentJobInfo, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(job).expect("JSON"));
    } else {
        println!(
            "{} {}",
            job.job_id,
            match job.state {
                AgentJobState::Queued => "queued",
                AgentJobState::Running => "running",
                AgentJobState::Succeeded => "succeeded",
                AgentJobState::Failed => "failed",
                AgentJobState::Canceled => "canceled",
                AgentJobState::Interrupted => "interrupted",
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onec_agent_protocol::NativeExecutionEffect;
    use std::collections::BTreeMap;

    fn sample_policy() -> NativeSuitePolicy {
        NativeSuitePolicy {
            version: 1,
            runner_sha256: "11".repeat(32),
            args: vec!["--exact".to_owned(), "suite::case".to_owned()],
            env: BTreeMap::new(),
            expected_tests: vec!["suite::case".to_owned()],
            effect: NativeExecutionEffect::RunOwned,
        }
    }

    #[test]
    fn native_suite_policy_reader_accepts_bounded_regular_json_file() {
        let directory = tempfile::tempdir().expect("policy fixture directory");
        let path = directory.path().join("suite-policy.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&sample_policy()).expect("serialize policy"),
        )
        .expect("write policy");

        assert_eq!(
            read_native_suite_policy(&path).expect("read policy"),
            sample_policy()
        );
    }

    #[test]
    fn cache_only_start_rejects_mapped_files_before_reservation_or_remote_setup() {
        assert!(validate_cache_only_options(true, &[]).is_ok());
        let error = validate_cache_only_options(true, &["INPUT_FILE".to_owned()])
            .expect_err("mapped files require transfer and are forbidden in cache-only mode");
        assert!(error.to_string().contains("--map-file-env"));
        assert!(validate_cache_only_options(false, &["INPUT_FILE".to_owned()]).is_ok());

        let source = include_str!("run_local_job.rs");
        let validation = source
            .find("validate_cache_only_options(require_cached_candidate, &mapped_env)")
            .expect("cache-only argument validation");
        let reserve = source
            .find("mutable_lease::reserve_durable_run_local")
            .expect("durable reservation");
        assert!(validation < reserve);
        let native_effect_validation = source
            .find("if native_effect == onec_agent_protocol::NativeExecutionEffect::ReadOnly")
            .expect("durable native execution effect validation");
        let capability_gate = source
            .find("client.require_local_candidate_job_support().await?")
            .expect("agent capability preflight");
        assert!(native_effect_validation < reserve);
        assert!(capability_gate < reserve);
    }

    #[test]
    fn cache_only_candidate_check_is_repeated_before_submission_and_skips_candidate_publisher() {
        let source = include_str!("run_local_job.rs");
        let cache_admission = source
            .find("\"cache_admission\"")
            .expect("cache-admission Agent identity check");
        let candidate_check = source
            .find("\"pre_submission\"")
            .expect("pre-submission Agent cache identity check");
        let submission = source
            .find("job_submission_attempted = true")
            .expect("tracked job submission boundary");
        assert!(cache_admission < candidate_check);
        assert!(candidate_check < submission);

        let normalized_indentation = source.lines().map(str::trim).collect::<Vec<_>>().join("\n");
        assert!(
            normalized_indentation
                .contains("if !require_cached_candidate {\nsuper::transport::publish_or_reuse(")
        );
    }

    #[test]
    fn native_suite_policy_reader_rejects_directories_and_oversized_files() {
        let directory = tempfile::tempdir().expect("policy fixture directory");
        let directory_error = read_native_suite_policy(directory.path())
            .expect_err("directory is not a regular policy file");
        assert!(directory_error.to_string().contains("regular file"));

        let path = directory.path().join("oversized.json");
        let file = std::fs::File::create(&path).expect("create oversized policy");
        file.set_len(MAX_NATIVE_SUITE_POLICY_BYTES + 1)
            .expect("size oversized policy");
        let oversized_error =
            read_native_suite_policy(&path).expect_err("oversized policy must fail closed");
        assert!(oversized_error.to_string().contains("1 MiB size limit"));
    }

    #[test]
    fn policy_capability_preflight_precedes_every_remote_mutation() {
        let source = include_str!("run_local_job.rs");
        let policy_gate = source
            .find("require_capability(\"native-suite-policy-admission-v1\")")
            .expect("policy capability preflight");
        let reserve = source
            .find("mutable_lease::reserve_durable_run_local")
            .expect("durable reservation");
        let prepare = source
            .find("client.prepare_run_local_job")
            .expect("remote preparation");
        let upload = source
            .find("super::transport::publish_or_reuse")
            .expect("remote upload");
        assert!(policy_gate < reserve);
        assert!(policy_gate < prepare);
        assert!(policy_gate < upload);
    }
}
