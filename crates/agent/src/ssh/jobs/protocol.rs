use super::wire::{JobRequest, JobResponse};
use super::*;

pub(super) async fn handle_job_request(
    request: JobRequest,
    runtime: &Arc<JobRuntime>,
    owner: &str,
) -> JobResponse {
    let (version, id_text) = match &request {
        JobRequest::Start { version, id, .. }
        | JobRequest::Status { version, id }
        | JobRequest::Cancel { version, id }
        | JobRequest::Output { version, id, .. } => (*version, id.as_str()),
        JobRequest::Seal { .. } => unreachable!("seal requests are handled before job dispatch"),
    };
    if version != 1 {
        return JobResponse::error("unsupported jobs-v1 version");
    }
    let Ok(id) = JobId::parse(id_text) else {
        return JobResponse::error("invalid job ID");
    };
    match request {
        JobRequest::Start { spec, .. } => {
            let _start = runtime.start_lock.lock().await;
            if !runtime.accepting.load(Ordering::Acquire) {
                return JobResponse::error("Agent is shutting down");
            }
            let admission = match runtime.store.admit(id, owner, &spec).await {
                Ok(admission) => admission,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return JobResponse::error("job belongs to another controller");
                }
                Err(_) => return JobResponse::error("job admission failed"),
            };
            match admission {
                Admission::Existing(record) => {
                    JobResponse::success(record.id.to_string(), record.state)
                }
                Admission::Created(_) => {
                    if verify_job_source(&spec).is_err() {
                        let _ = runtime
                            .store
                            .transition(id, owner, JobState::Prepared, JobState::Failed)
                            .await;
                        return JobResponse::error("source executable verification failed");
                    }
                    let permit = match runtime.slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = runtime
                                .store
                                .transition(id, owner, JobState::Prepared, JobState::Failed)
                                .await;
                            return JobResponse::error("active job limit reached");
                        }
                    };
                    // Commit the immutable, once-only start claim before any OS process.
                    // A lost SSH acknowledgement cannot make this UUID eligible again.
                    let record = match runtime.store.claim_start(id, owner).await {
                        Ok(record) => record,
                        Err(_) => return JobResponse::error("job start reservation failed"),
                    };
                    let active = Arc::new(JobCancellation {
                        process: runtime.shutdown.child_token(),
                        requested: AtomicBool::new(false),
                    });
                    runtime
                        .active_jobs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(id, active.clone());
                    let runtime = runtime.clone();
                    let owner = owner.to_owned();
                    let response = JobResponse::success(id.to_string(), JobState::Running);
                    tokio::spawn(async move {
                        let _permit = permit;
                        if run_job(runtime.clone(), owner, record, active)
                            .await
                            .is_err()
                        {
                            // No terminal state was published: the durable started claim
                            // remains blocked for recovery, and is never re-enqueued.
                            eprintln!(
                                "hostlink-agent: durable job {id} state persistence failed; its started claim blocks update"
                            );
                        }
                        runtime
                            .active_jobs
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&id);
                    });
                    response
                }
            }
        }
        JobRequest::Status { .. } => match runtime.store.lookup(id, owner).await {
            Ok(record) => JobResponse::success(record.id.to_string(), record.state),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                JobResponse::error("job belongs to another controller")
            }
            Err(_) => JobResponse::error("job status unavailable"),
        },
        JobRequest::Cancel { .. } => {
            // Serialize with admission: only the actual authenticated controller
            // may cancel the Agent-owned worker, never the SSH channel itself.
            let _start = runtime.start_lock.lock().await;
            let record = match runtime.store.lookup(id, owner).await {
                Ok(record) => record,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return JobResponse::error("job belongs to another controller");
                }
                Err(_) => return JobResponse::error("job status unavailable"),
            };
            match record.state {
                JobState::Running => {
                    let active = runtime
                        .active_jobs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&id)
                        .cloned();
                    let Some(active) = active else {
                        // A persisted Running record without a worker is ambiguous.
                        return JobResponse::error("job cancellation unavailable");
                    };
                    active.requested.store(true, Ordering::Release);
                    active.process.cancel();
                    // Cancellation is not terminal until the process tree is gone.
                    JobResponse::success(id.to_string(), JobState::Running)
                }
                JobState::Prepared | JobState::Interrupted => {
                    JobResponse::error("job has no cancellable worker")
                }
                state => JobResponse::success(id.to_string(), state),
            }
        }
        JobRequest::Output { stream, offset, .. } => {
            match runtime.store.read_output(id, owner, stream, offset).await {
                Ok((data, next, eof)) => {
                    let Ok(record) = runtime.store.lookup(id, owner).await else {
                        return JobResponse::error("job status unavailable");
                    };
                    let mut response = JobResponse::success(record.id.to_string(), record.state);
                    use base64::Engine as _;
                    response.data_base64 =
                        Some(base64::engine::general_purpose::STANDARD.encode(data));
                    response.next_offset = Some(next);
                    response.eof = Some(eof);
                    response
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    JobResponse::error("job belongs to another controller")
                }
                Err(_) => JobResponse::error("job output unavailable"),
            }
        }
        JobRequest::Seal { .. } => unreachable!("seal requests are handled before job dispatch"),
    }
}
