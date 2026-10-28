use super::frame::JobRequest;
use super::*;
use serde_json::{Value, json};

pub(super) async fn handle_job_request(
    request: JobRequest,
    runtime: &Arc<JobRuntime>,
    owner: &str,
) -> Result<Value, &'static str> {
    match request {
        JobRequest::Seal { name, sha256, size } => {
            let program = runtime
                .store
                .artifacts(owner)
                .and_then(|a| a.seal(&name, &sha256, size))
                .map_err(|_| "artifact seal failed")?;
            Ok(json!({"ok":true,"program":program,"sha256":sha256}))
        }
        JobRequest::List { page, status } => {
            let jobs = runtime
                .store
                .list(owner, page, status.as_deref())
                .await
                .map_err(|_| "job list unavailable")?;
            Ok(json!({"ok":true,"jobs":jobs}))
        }
        JobRequest::Run { id, spec } => {
            let _start = runtime.start_lock.lock().await;
            if !runtime.accepting.load(Ordering::Acquire) {
                return Err("Agent is shutting down");
            }
            // A lost ACK retry returns its immutable record even if the source
            // was later removed. admit still checks exact owner/spec identity;
            // this branch cannot grant a new execution attempt.
            if runtime
                .store
                .find(id, owner)
                .await
                .map_err(|_| "job admission failed")?
                .is_none()
            {
                verify_job_source(&runtime.store, owner, &spec)
                    .map_err(|_| "job source authorization failed")?;
            }
            Ok(status_reply(
                id,
                runtime
                    .store
                    .admit(id, owner, &spec)
                    .await
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::WouldBlock {
                            "Agent update busy"
                        } else {
                            "job admission failed"
                        }
                    })?
                    .state,
            ))
        }
        JobRequest::Status { id } => Ok(status_reply(
            id,
            runtime
                .store
                .lookup(id, owner)
                .await
                .map_err(|_| "job status unavailable")?
                .state,
        )),
        JobRequest::Cancel { id } => {
            // Only the authenticated owner may cancel; channel lifetime is irrelevant.
            let _start = runtime.start_lock.lock().await;
            let record = runtime
                .store
                .lookup(id, owner)
                .await
                .map_err(|_| "job status unavailable")?;
            let state = match record.state {
                JobState::Running => {
                    let active = runtime
                        .active_jobs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&id)
                        .cloned()
                        .ok_or("job cancellation unavailable")?;
                    active.cancel();
                    JobState::Running // Terminal only after confirmed tree teardown.
                }
                JobState::Prepared => {
                    runtime
                        .store
                        .transition(id, owner, JobState::Prepared, JobState::Failed)
                        .await
                        .map_err(|_| "job cancellation unavailable")?
                        .state
                }
                JobState::Interrupted => return Err("job has no cancellable worker"),
                state => state,
            };
            Ok(status_reply(id, state))
        }
        JobRequest::Logs { id, stream, offset } => {
            let record = runtime
                .store
                .lookup(id, owner)
                .await
                .map_err(|_| "job output unavailable")?;
            let (data, next, eof) = runtime
                .store
                .read_output(&record, stream, offset)
                .map_err(|_| "job output unavailable")?;
            use base64::Engine as _;
            Ok(json!({"ok":true,"id":id.to_string(),"state":record.state,
                "data_base64":base64::engine::general_purpose::STANDARD.encode(data),"next_offset":next,"eof":eof}))
        }
    }
}

fn status_reply(id: JobId, state: JobState) -> Value {
    json!({"ok":true,"id":id.to_string(),"state":state,"data_base64":null,"next_offset":null,"eof":null})
}
