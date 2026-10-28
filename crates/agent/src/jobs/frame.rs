use super::protocol::handle_job_request;
use super::*;

pub(crate) async fn handle_job_channel(
    channel: Channel<Msg>,
    runtime: Arc<JobRuntime>,
    owner: String,
) {
    let mut stream = channel.into_stream();
    let response = async {
        let bytes = tokio::time::timeout(JOB_REQUEST_TIMEOUT, read_job_frame(&mut stream))
            .await
            .map_err(|_| "jobs request timed out")?
            .map_err(|_| "invalid jobs frame")?;
        let request = serde_json::from_slice(&bytes).map_err(|_| "malformed jobs request")?;
        handle_job_request(request, &runtime, &owner).await
    }
    .await
    .unwrap_or_else(|error| serde_json::json!({"ok":false,"error":error}));
    let body = serde_json::to_vec(&response).expect("jobs response contains only JSON values");
    if let Ok(size) = u32::try_from(body.len()) {
        let _ = stream.write_all(&size.to_be_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

async fn read_job_frame(stream: &mut russh::ChannelStream<Msg>) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > JOB_FRAME_MAX_BYTES {
        return Err(invalid_data("jobs request frame length is invalid"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    let mut trailing = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut trailing)).await {
        Ok(Ok(0)) => Ok(body),
        _ => Err(invalid_data("jobs accepts exactly one request frame")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum JobRequest {
    #[serde(rename = "list")]
    List { page: u32, status: Option<String> },
    #[serde(rename = "run")]
    Run { id: JobId, spec: JobSpec },
    #[serde(rename = "status")]
    Status { id: JobId },
    #[serde(rename = "cancel")]
    Cancel { id: JobId },
    #[serde(rename = "logs")]
    Logs {
        id: JobId,
        stream: JobOutput,
        offset: u64,
    },
    #[serde(rename = "seal")]
    Seal {
        name: String,
        sha256: String,
        size: u64,
    },
}
