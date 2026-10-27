use russh::ChannelMsg;
use serde_json::Value;

use super::{
    model::{Cancel, JobOutput, JobStatus, Output, Seal, SealedArtifact, Start, Status},
    protocol::{
        MAX_FRAME_BYTES, SUBSYSTEM, SealSuccessReply, close_channel, decode_frame, parse_output,
        parse_remote_error, parse_status, protocol_error, protocol_invalid, require_keys,
        sealed_artifact_name,
    },
    validation::{validate_absolute_path, validate_id, validate_spec},
};
use crate::connect::{HostConnection, OPERATION_TIMEOUT, SshClientError};

impl HostConnection {
    /// Asks the Agent to verify and seal one staged artifact over jobs-v1.
    ///
    /// # Errors
    /// Returns an error for invalid request values, malformed protocol replies,
    /// a digest mismatch, or transport failure.
    pub async fn job_seal(&mut self, request: &Seal) -> Result<SealedArtifact, SshClientError> {
        if request.size > 64 * 1024 * 1024 || request.name != sealed_artifact_name(&request.sha256)?
        {
            return Err(protocol_invalid("invalid Seal request"));
        }
        let value = self
            .job_request(serde_json::json!({
                "version": 1,
                "op": "seal",
                "name": request.name,
                "sha256": request.sha256,
                "size": request.size,
            }))
            .await?;
        if value.get("ok") == Some(&Value::Bool(false)) {
            return Err(parse_remote_error(value)?);
        }
        require_keys(&value, &["version", "ok", "program", "sha256"])?;
        let reply: SealSuccessReply = serde_json::from_value(value)
            .map_err(|_| protocol_invalid("Seal reply fields are missing or unknown"))?;
        if reply.version != 1 || !reply.ok || reply.sha256 != request.sha256 {
            return Err(protocol_invalid(
                "Seal reply version, success flag, or digest mismatch",
            ));
        }
        validate_absolute_path(&reply.program)
            .map_err(|_| protocol_invalid("Seal reply program is not an absolute path"))?;
        Ok(SealedArtifact {
            program: reply.program,
            sha256: reply.sha256,
        })
    }

    /// Starts one Agent-owned durable job request over a fresh SSH channel.
    ///
    /// A transport failure may mean the Agent accepted the request without
    /// delivering its reply. The caller must query this ID after reconnecting;
    /// this method never retries the start request.
    pub async fn job_start(&mut self, request: &Start) -> Result<JobStatus, SshClientError> {
        validate_id(&request.id)?;
        validate_spec(&request.spec)?;
        let body = serde_json::json!({
            "version": 1,
            "op": "start",
            "id": request.id,
            "spec": request.spec,
        });
        let value = self.job_request(body).await?;
        parse_status(value, &request.id)
    }

    /// Reads a previously admitted job state over a new subsystem channel.
    pub async fn job_status(&mut self, request: &Status) -> Result<JobStatus, SshClientError> {
        validate_id(&request.id)?;
        let value = self
            .job_request(serde_json::json!({ "version": 1, "op": "status", "id": request.id }))
            .await?;
        parse_status(value, &request.id)
    }

    /// Requests cancellation without claiming a running process is already terminated.
    ///
    /// On a lost ACK, query status after reconnecting; never replay a start.
    pub async fn job_cancel(&mut self, request: &Cancel) -> Result<JobStatus, SshClientError> {
        validate_id(&request.id)?;
        let value = self
            .job_request(serde_json::json!({ "version": 1, "op": "cancel", "id": request.id }))
            .await?;
        parse_status(value, &request.id)
    }

    /// Reads one bounded raw output chunk at the requested byte offset.
    pub async fn job_output(&mut self, request: &Output) -> Result<JobOutput, SshClientError> {
        validate_id(&request.id)?;
        let value = self
            .job_request(serde_json::json!({
                "version": 1,
                "op": "output",
                "id": request.id,
                "stream": request.stream,
                "offset": request.offset,
            }))
            .await?;
        parse_output(value, request)
    }

    async fn job_request(&mut self, body: Value) -> Result<Value, SshClientError> {
        let encoded = serde_json::to_vec(&body)
            .map_err(|_| protocol_invalid("request JSON could not be encoded"))?;
        if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
            return Err(protocol_invalid("request frame exceeds 64 KiB"));
        }
        let length = u32::try_from(encoded.len())
            .map_err(|_| protocol_invalid("request frame length overflow"))?;
        let mut frame = Vec::with_capacity(encoded.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&encoded);

        let deadline = tokio::time::Instant::now() + OPERATION_TIMEOUT;
        let channel = tokio::time::timeout_at(deadline, self.session.channel_open_session())
            .await
            .map_err(|_| SshClientError::Timeout)??;
        let (mut reader, writer) = channel.split();
        match tokio::time::timeout_at(deadline, writer.request_subsystem(true, SUBSYSTEM)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                close_channel(&writer).await;
                return Err(SshClientError::Timeout);
            }
        }
        match tokio::time::timeout_at(deadline, writer.data_bytes(frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                close_channel(&writer).await;
                return Err(SshClientError::Timeout);
            }
        }
        match tokio::time::timeout_at(deadline, writer.eof()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                close_channel(&writer).await;
                return Err(SshClientError::Timeout);
            }
        }

        let mut response = Vec::with_capacity(1024);
        let mut closed = false;
        while !closed {
            let message = tokio::time::timeout_at(deadline, reader.wait())
                .await
                .map_err(|_| SshClientError::Timeout)?;
            match message {
                Some(ChannelMsg::Data { data }) => {
                    if response.len().saturating_add(data.len()) > MAX_FRAME_BYTES + 4 {
                        close_channel(&writer).await;
                        return Err(protocol_invalid("response frame exceeds 64 KiB"));
                    }
                    response.extend_from_slice(&data);
                }
                Some(ChannelMsg::Close | ChannelMsg::Eof) | None => closed = true,
                Some(ChannelMsg::Success | ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::ExtendedData { .. }) => {
                    close_channel(&writer).await;
                    return Err(protocol_invalid("response must use channel data only"));
                }
                Some(_) => {
                    close_channel(&writer).await;
                    return Err(protocol_invalid("unexpected SSH message on jobs channel"));
                }
            }
        }
        decode_frame(&response).map_err(protocol_error)
    }
}
