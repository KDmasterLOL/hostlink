use super::protocol::handle_job_request;
use super::wire::JobRequest;
use super::*;

pub(in crate::ssh) async fn handle_job_channel(
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
