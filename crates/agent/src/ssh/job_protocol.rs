#![allow(unused_imports)]
use super::config::invalid_data;
use super::job_runtime::{JobCancellation, JobRuntime, run_job, verify_job_source};
use super::*;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum JobRequest {
    #[serde(rename = "start")]
    Start {
        version: u8,
        id: String,
        spec: JobSpec,
    },
    #[serde(rename = "status")]
    Status { version: u8, id: String },
    #[serde(rename = "cancel")]
    Cancel { version: u8, id: String },
    #[serde(rename = "output")]
    Output {
        version: u8,
        id: String,
        stream: JobOutput,
        offset: u64,
    },
    #[serde(rename = "seal")]
    Seal {
        version: u8,
        name: String,
        sha256: String,
        size: u64,
    },
}

#[derive(Serialize)]
struct JobResponse {
    version: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<JobState>,
    data_base64: Option<String>,
    next_offset: Option<u64>,
    eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

impl JobResponse {
    fn success(id: impl Into<String>, state: JobState) -> Self {
        Self {
            version: 1,
            ok: true,
            id: Some(id.into()),
            state: Some(state),
            data_base64: None,
            next_offset: None,
            eof: None,
            error: None,
        }
    }

    fn error(message: &'static str) -> Self {
        Self {
            version: 1,
            ok: false,
            id: None,
            state: None,
            data_base64: None,
            next_offset: None,
            eof: None,
            error: Some(message),
        }
    }
}

pub(super) async fn handle_job_channel(
    channel: Channel<Msg>,
    runtime: Arc<JobRuntime>,
    owner: String,
) {
    let mut stream = channel.into_stream();
    let body = match tokio::time::timeout(JOB_REQUEST_TIMEOUT, read_job_frame(&mut stream)).await {
        Err(_) => error_job_body(1, "jobs-v1 request timed out"),
        Ok(Err(_)) => error_job_body(1, "invalid jobs-v1 frame"),
        Ok(Ok(bytes)) => match serde_json::from_slice::<JobRequest>(&bytes) {
            Ok(JobRequest::Seal {
                version,
                name,
                sha256,
                size,
            }) => {
                let result = if version != 1 {
                    Err("unsupported jobs-v1 version")
                } else {
                    runtime
                        .store
                        .artifacts(&owner)
                        .and_then(|artifacts| artifacts.seal(&name, &sha256, size))
                        .map_err(|_| "artifact seal failed")
                };
                match result {
                    Ok(program) => serde_json::to_vec(&serde_json::json!({"version":1,"ok":true,"program":program,"sha256":sha256})),
                    Err(error) => Ok(error_job_body(1, error)),
                }
                .unwrap_or_else(|_| error_job_body(1, "response encoding failed"))
            }
            Ok(request) => {
                let response = handle_job_request(request, &runtime, &owner).await;
                if response.ok {
                    serde_json::to_vec(&response)
                        .unwrap_or_else(|_| error_job_body(1, "response encoding failed"))
                } else {
                    error_job_body(
                        response.version,
                        response.error.unwrap_or("jobs-v1 request failed"),
                    )
                }
            }
            Err(_) => error_job_body(1, "malformed jobs-v1 request"),
        },
    };
    if let Ok(size) = u32::try_from(body.len()) {
        let _ = stream.write_all(&size.to_be_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

fn error_job_body(version: u8, error: &'static str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":version,"ok":false,"error":error}))
        .unwrap_or_else(|_| {
            br#"{"version":1,"ok":false,"error":"response encoding failed"}"#.to_vec()
        })
}

async fn read_job_frame(stream: &mut russh::ChannelStream<Msg>) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > JOB_FRAME_MAX_BYTES {
        return Err(invalid_data("jobs-v1 request frame length is invalid"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let mut trailing = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut trailing)).await {
        Ok(Ok(0)) => Ok(body),
        _ => Err(invalid_data("jobs-v1 accepts exactly one request frame")),
    }
}

async fn handle_job_request(
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
            let admission = match runtime.store.admit(id, owner, &spec) {
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
                Admission::Created(record) => {
                    if verify_job_source(&spec).is_err() {
                        let _ = runtime.store.transition(
                            id,
                            owner,
                            JobState::Prepared,
                            JobState::Failed,
                        );
                        return JobResponse::error("source executable verification failed");
                    }
                    let permit = match runtime.slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = runtime.store.transition(
                                id,
                                owner,
                                JobState::Prepared,
                                JobState::Failed,
                            );
                            return JobResponse::error("active job limit reached");
                        }
                    };
                    if runtime
                        .store
                        .transition(id, owner, JobState::Prepared, JobState::Running)
                        .is_err()
                    {
                        let _ = runtime.store.transition(
                            id,
                            owner,
                            JobState::Prepared,
                            JobState::Failed,
                        );
                        return JobResponse::error("job start reservation failed");
                    }
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
                        run_job(runtime.clone(), owner, record, active).await;
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
        JobRequest::Status { .. } => match runtime.store.lookup(id, owner) {
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
            let record = match runtime.store.lookup(id, owner) {
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
            match runtime.store.read_output(id, owner, stream, offset) {
                Ok((data, next, eof)) => {
                    let Ok(record) = runtime.store.lookup(id, owner) else {
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
