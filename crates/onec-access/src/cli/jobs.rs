use super::*;

pub(super) async fn wait_for_job_status<F, Fut>(
    job_id: &str,
    interval: Duration,
    timeout_seconds: Option<u64>,
    mut job_status: F,
) -> AppResult<AgentJobInfo>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = AppResult<AgentResponseKind>>,
{
    let started = tokio::time::Instant::from_std(Instant::now());
    let deadline =
        timeout_seconds.and_then(|seconds| started.checked_add(Duration::from_secs(seconds)));
    loop {
        let response = if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, job_status(job_id.to_owned()))
                .await
                .map_err(|_| job_wait_timeout(job_id))??
        } else {
            job_status(job_id.to_owned()).await?
        };
        let AgentResponseKind::JobStatus { job } = response else {
            return Err(crate::invalid_config(
                "remote agent returned a non-job-status response".to_owned(),
            ));
        };
        if job.state.is_terminal() {
            return Ok(job);
        }

        if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, tokio::time::sleep(interval))
                .await
                .map_err(|_| job_wait_timeout(job_id))?;
        } else {
            tokio::time::sleep(interval).await;
        }
    }
}

pub(super) fn job_wait_timeout(job_id: &str) -> anyhow::Error {
    crate::invalid_config(format!(
        "timed out waiting for managed job {job_id}; the job remains owned by onec-agent"
    ))
}

pub(super) async fn client(name: &str) -> AppResult<RemoteAgentClient> {
    let server = resolve_remote_server(name).await?;
    RemoteAgentClient::new(server)
}

pub(super) fn state_name(state: AgentJobState) -> &'static str {
    match state {
        AgentJobState::Queued => "queued",
        AgentJobState::Running => "running",
        AgentJobState::Succeeded => "succeeded",
        AgentJobState::Failed => "failed",
        AgentJobState::Canceled => "canceled",
        AgentJobState::Interrupted => "interrupted",
    }
}

pub(super) fn print_job(job: &AgentJobInfo, json_output: bool) {
    if json_output {
        crate::cli::output::print_pretty_json(job);
    } else {
        println!(
            "{}\t{}\texit={}",
            job.job_id,
            state_name(job.state),
            job.exit_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        if job.stdout_log_truncated {
            println!("stdout durable log: truncated by storage bound");
        }
        if job.stderr_log_truncated {
            println!("stderr durable log: truncated by storage bound");
        }
        if let Some(message) = &job.message {
            println!("{message}");
        }
    }
}

pub(super) fn parse_env(values: &[String]) -> AppResult<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for value in values {
        let (name, value) = value.split_once('=').ok_or_else(|| {
            crate::invalid_config(format!("--env expects KEY=VALUE, got {value:?}"))
        })?;
        super::secrets::validate_environment_name(name)?;
        if value.contains('\0') {
            return Err(crate::invalid_config(format!(
                "invalid environment assignment for {name:?}"
            )));
        }
        if env.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(crate::invalid_config(format!(
                "--env repeats variable {name:?}"
            )));
        }
    }
    Ok(env)
}

pub(super) fn parse_result_specs(
    values: &[String],
) -> AppResult<Vec<onec_agent_protocol::ResultArtifactSpec>> {
    let mut results = Vec::with_capacity(values.len());
    for value in values {
        let (name, max_bytes) = value.split_once('=').ok_or_else(|| {
            crate::invalid_config(format!("--result expects NAME=MAX_BYTES, got {value:?}"))
        })?;
        let max_bytes = max_bytes.parse::<u64>().map_err(|error| {
            crate::invalid_config(format!("invalid --result byte limit in {value:?}: {error}"))
        })?;
        results.push(
            onec_agent_protocol::ResultArtifactSpec::try_new(name.to_owned(), max_bytes, None)
                .map_err(crate::invalid_config)?,
        );
    }
    onec_agent_protocol::validate_result_specs(&results).map_err(crate::invalid_config)?;
    Ok(results)
}

pub(super) async fn download_result_set(
    client: &RemoteAgentClient,
    result_set: &onec_agent_protocol::ResultSetInfo,
    local_dir: &std::path::Path,
    overwrite: bool,
    cleanup: bool,
) -> AppResult<()> {
    for artifact in result_set.artifacts() {
        client
            .result_download(
                result_set.owner().clone(),
                artifact,
                local_dir.join(artifact.name()),
                overwrite,
            )
            .await?;
    }
    if cleanup {
        client.result_cleanup(result_set.owner().clone()).await?;
    }
    Ok(())
}

#[cfg(test)]
fn download_result_artifacts_then_cleanup<D, C>(
    result_set: &onec_agent_protocol::ResultSetInfo,
    local_dir: &std::path::Path,
    overwrite: bool,
    cleanup: bool,
    mut download: D,
    cleanup_owner: C,
) -> AppResult<()>
where
    D: FnMut(
        &onec_agent_protocol::ResultOwner,
        &onec_agent_protocol::ResultArtifactInfo,
        PathBuf,
        bool,
    ) -> AppResult<()>,
    C: FnOnce(onec_agent_protocol::ResultOwner) -> AppResult<bool>,
{
    for artifact in result_set.artifacts() {
        let path = local_dir.join(artifact.name());
        download(result_set.owner(), artifact, path, overwrite)?;
    }
    if cleanup {
        cleanup_owner(result_set.owner().clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_deadline_bounds_delayed_status_without_canceling_the_durable_job() {
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            wait_for_job_status("job-1", Duration::from_millis(100), Some(1), |_| {
                let requests = std::sync::Arc::clone(&requests);
                async move {
                    requests.lock().expect("request log").push("job_status");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(AgentResponseKind::JobStatus {
                        job: AgentJobInfo {
                            job_id: "job-1".to_owned(),
                            state: AgentJobState::Running,
                            worker_pid: None,
                            spawn_owner_pid: None,
                            process_pid: None,
                            exit_code: None,
                            created_unix_ms: 0,
                            started_unix_ms: None,
                            finished_unix_ms: None,
                            message: None,
                            stdout_log_truncated: false,
                            stderr_log_truncated: false,
                            result_set: None,
                            run_local: None,
                        },
                    })
                }
            }),
        )
        .await
        .expect("the wait deadline should interrupt a delayed status RPC");

        let error = result.expect_err("a one-second wait deadline should time out");
        assert!(
            error
                .to_string()
                .contains("the job remains owned by onec-agent")
        );
        assert_eq!(
            *requests.lock().expect("request log"),
            vec!["job_status"],
            "wait timeout must not send a cancellation request"
        );
    }

    #[test]
    fn environment_overrides_are_typed_and_duplicate_safe() {
        let parsed = parse_env(&["A=1".into(), "UNICODE=Привет".into()]).expect("env");
        assert_eq!(parsed["A"], "1");
        assert_eq!(parsed["UNICODE"], "Привет");
        assert!(parse_env(&["A=1".into(), "A=2".into()]).is_err());
        assert!(parse_env(&["missing-separator".into()]).is_err());
    }

    #[test]
    fn result_declarations_use_protocol_validation_and_reject_case_duplicates() {
        let parsed = parse_result_specs(&["report.bin=1024".into()]).expect("result spec");
        assert_eq!(parsed[0].name(), "report.bin");
        assert_eq!(parsed[0].max_bytes(), 1024);
        assert_eq!(parsed[0].media_type(), None);
        assert!(parse_result_specs(&["Report.bin=10".into(), "report.bin=20".into()]).is_err());
        assert!(parse_result_specs(&["../escape=10".into()]).is_err());
        assert!(parse_result_specs(&["missing-limit".into()]).is_err());
        assert!(parse_result_specs(&["empty=0".into()]).is_err());
    }

    #[test]
    fn result_cleanup_runs_after_every_publication_and_is_skipped_on_failure() {
        let result_set = onec_agent_protocol::ResultSetInfo::try_new(
            onec_agent_protocol::ResultOwner::job("job-1").expect("valid owner"),
            ["first.bin", "second.bin"]
                .into_iter()
                .map(|name| {
                    onec_agent_protocol::ResultArtifactInfo::try_new(
                        name.to_owned(),
                        1,
                        "a".repeat(64),
                        None,
                    )
                    .expect("valid artifact metadata")
                })
                .collect(),
        )
        .expect("valid result set");
        let successful_order = std::cell::RefCell::new(Vec::new());
        download_result_artifacts_then_cleanup(
            &result_set,
            std::path::Path::new("local"),
            false,
            true,
            |_, artifact, _, _| {
                successful_order
                    .borrow_mut()
                    .push(format!("published:{}", artifact.name()));
                Ok(())
            },
            |_| {
                successful_order.borrow_mut().push("cleanup".to_owned());
                Ok(true)
            },
        )
        .expect("all artifacts should publish before cleanup");
        assert_eq!(
            *successful_order.borrow(),
            vec![
                "published:first.bin".to_owned(),
                "published:second.bin".to_owned(),
                "cleanup".to_owned()
            ]
        );

        let failed_order = std::cell::RefCell::new(Vec::new());
        let error = download_result_artifacts_then_cleanup(
            &result_set,
            std::path::Path::new("local"),
            false,
            true,
            |_, artifact, _, _| {
                failed_order
                    .borrow_mut()
                    .push(format!("download:{}", artifact.name()));
                if artifact.name() == "second.bin" {
                    return Err(crate::invalid_config("publication failed".to_owned()));
                }
                Ok(())
            },
            |_| {
                failed_order.borrow_mut().push("cleanup".to_owned());
                Ok(true)
            },
        )
        .expect_err("a publication error must preserve the target result set");
        assert!(error.to_string().contains("publication failed"));
        assert_eq!(
            *failed_order.borrow(),
            vec![
                "download:first.bin".to_owned(),
                "download:second.bin".to_owned()
            ]
        );
    }
}
