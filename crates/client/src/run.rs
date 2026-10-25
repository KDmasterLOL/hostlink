//! Durable jobs over the authenticated `hostlink-jobs-v1` SSH subsystem.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use russh::{ChannelMsg, ChannelWriteHalf, client::Msg};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::connect::{HostConnection, OPERATION_TIMEOUT, SshClientError};

const SUBSYSTEM: &str = "hostlink-jobs-v1";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_CHUNK_BYTES: usize = 24 * 1024;
const CHANNEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Job identifier must be a canonical lowercase UUID.
pub type JobId = String;

/// Executable and exact argument vector admitted for a durable job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Absolute executable path.
    pub program: String,
    /// Arguments passed without shell interpretation.
    pub args: Vec<String>,
    /// Optional working directory.
    pub cwd: Option<String>,
    /// Lowercase SHA-256 digest of the executable.
    pub source_sha256: String,
}

/// One idempotent admission request. Reusing this ID never implies a retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// Canonical lowercase UUID chosen by the caller.
    pub id: JobId,
    /// Exact executable and argv manifest.
    pub spec: JobSpec,
}

/// Status query for a previously admitted job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Status {
    /// Canonical lowercase UUID returned by the original start request.
    pub id: JobId,
}

/// Requests cancellation by canonical durable job identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Cancel {
    pub id: JobId,
}

/// Selects one persisted output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Reads bytes starting at a persisted byte offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    /// Canonical lowercase UUID returned by the original start request.
    pub id: JobId,
    /// Output stream to read.
    pub stream: JobStream,
    /// Exact byte offset from which to continue.
    pub offset: u64,
}

/// Requests Agent-side verification and sealing of the exclusively uploaded artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seal {
    /// Digest-bound SFTP staging name: `<sha256>.upload`.
    pub name: String,
    /// Expected lowercase SHA-256 digest.
    pub sha256: String,
    /// Exact uploaded byte length.
    pub size: u64,
}

/// Agent-resolved executable path and verified artifact digest.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedArtifact {
    /// Canonical absolute path selected by the Agent.
    pub program: String,
    /// Digest verified by the Agent.
    pub sha256: String,
}

/// Persisted Agent job lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStateKind {
    /// Accepted but not yet running.
    Prepared,
    /// Worker is running.
    Running,
    /// Worker exited; `code` preserves its actual exit code.
    Exited,
    /// Agent recorded a worker failure.
    Failed,
    /// Agent restarted or otherwise lost the worker before terminal state.
    Interrupted,
}

/// Exact status returned by the Agent.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStatus {
    /// Canonical lowercase job UUID.
    pub id: JobId,
    /// Current persisted lifecycle state.
    pub state: JobState,
}

/// Lifecycle data, retaining a nonzero process exit code.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobState {
    /// Exact state name.
    pub state: JobStateKind,
    /// Process exit code when known.
    #[serde(default)]
    pub code: Option<i32>,
}

/// One decoded raw output chunk and its continuation point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobOutput {
    /// Job lifecycle state observed with this read.
    pub status: JobStatus,
    /// Raw, possibly non-UTF-8 bytes.
    pub data: Vec<u8>,
    /// Offset to use for the next request.
    pub next_offset: u64,
    /// Whether this stream has reached EOF.
    pub eof: bool,
}

#[derive(Debug, Error)]
enum ProtocolError {
    #[error("invalid jobs-v1 response: {0}")]
    Invalid(&'static str),
}

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

/// Builds the only accepted SFTP staging name for a verified artifact digest.
///
/// # Errors
/// Returns an error unless `sha256` is exactly 64 lowercase hexadecimal characters.
pub fn sealed_artifact_name(sha256: &str) -> Result<String, SshClientError> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(protocol_invalid(
            "artifact SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(format!("{sha256}.upload"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealSuccessReply {
    version: u8,
    ok: bool,
    program: String,
    sha256: String,
}

fn validate_absolute_path(value: &str) -> Result<(), ()> {
    let absolute = std::path::Path::new(value).is_absolute()
        || (value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic))
        || value.starts_with("\\\\");
    if absolute && !value.is_empty() && !value.as_bytes().contains(&0) {
        Ok(())
    } else {
        Err(())
    }
}

async fn close_channel(channel: &ChannelWriteHalf<Msg>) {
    let _ = tokio::time::timeout(CHANNEL_CLEANUP_TIMEOUT, channel.close()).await;
}

fn decode_frame(bytes: &[u8]) -> Result<Value, ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::Invalid("missing or partial response frame"));
    }
    let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::Invalid("invalid response frame length"));
    }
    if bytes.len() != length + 4 {
        return Err(ProtocolError::Invalid(
            "partial or trailing response frame data",
        ));
    }
    serde_json::from_slice(&bytes[4..]).map_err(|_| ProtocolError::Invalid("invalid response JSON"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessReply {
    version: u8,
    ok: bool,
    id: String,
    state: JobState,
    data_base64: Option<String>,
    next_offset: Option<u64>,
    eof: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorReply {
    version: u8,
    ok: bool,
    error: String,
}

fn parse_status(value: Value, expected_id: &str) -> Result<JobStatus, SshClientError> {
    if value.get("ok") == Some(&Value::Bool(false)) {
        return Err(parse_remote_error(value)?);
    }
    require_keys(
        &value,
        &[
            "version",
            "ok",
            "id",
            "state",
            "data_base64",
            "next_offset",
            "eof",
        ],
    )?;
    let raw = value.clone();
    let reply: SuccessReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("status reply fields are missing or unknown"))?;
    if reply.version != 1 || !reply.ok || reply.id != expected_id {
        return Err(protocol_invalid(
            "status reply version, success flag, or ID mismatch",
        ));
    }
    if reply.data_base64.is_some() || reply.next_offset.is_some() || reply.eof.is_some() {
        return Err(protocol_invalid("status reply contains output fields"));
    }
    validate_state_shape(&raw, &reply.state)?;
    validate_returned_status(&reply.id, &reply.state)?;
    Ok(JobStatus {
        id: reply.id,
        state: reply.state,
    })
}

fn parse_output(value: Value, request: &Output) -> Result<JobOutput, SshClientError> {
    if value.get("ok") == Some(&Value::Bool(false)) {
        return Err(parse_remote_error(value)?);
    }
    require_keys(
        &value,
        &[
            "version",
            "ok",
            "id",
            "state",
            "data_base64",
            "next_offset",
            "eof",
        ],
    )?;
    let raw = value.clone();
    let reply: SuccessReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("output reply fields are missing or unknown"))?;
    if reply.version != 1 || !reply.ok || reply.id != request.id {
        return Err(protocol_invalid(
            "output reply version, success flag, or ID mismatch",
        ));
    }
    let data = reply
        .data_base64
        .ok_or_else(|| protocol_invalid("output reply omitted data_base64"))?;
    let next_offset = reply
        .next_offset
        .ok_or_else(|| protocol_invalid("output reply omitted next_offset"))?;
    let eof = reply
        .eof
        .ok_or_else(|| protocol_invalid("output reply omitted eof"))?;
    validate_state_shape(&raw, &reply.state)?;
    validate_returned_status(&reply.id, &reply.state)?;
    let decoded = STANDARD
        .decode(data)
        .map_err(|_| protocol_invalid("invalid Base64 output"))?;
    if decoded.len() > MAX_OUTPUT_CHUNK_BYTES {
        return Err(protocol_invalid("decoded output chunk exceeds 24 KiB"));
    }
    let expected_next = request
        .offset
        .checked_add(decoded.len() as u64)
        .ok_or_else(|| protocol_invalid("output offset overflow"))?;
    if next_offset != expected_next {
        return Err(protocol_invalid("output next_offset is inconsistent"));
    }
    Ok(JobOutput {
        status: JobStatus {
            id: reply.id,
            state: reply.state,
        },
        data: decoded,
        next_offset,
        eof,
    })
}

fn parse_remote_error(value: Value) -> Result<SshClientError, SshClientError> {
    require_keys(&value, &["version", "ok", "error"])?;
    let reply: ErrorReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("error reply fields are missing or unknown"))?;
    if reply.version != 1 || reply.ok || reply.error.is_empty() || reply.error.len() > 512 {
        return Err(protocol_invalid("invalid bounded remote error reply"));
    }
    Ok(SshClientError::Invalid(format!(
        "remote jobs-v1 error: {}",
        reply.error
    )))
}

fn validate_state_shape(value: &Value, parsed: &JobState) -> Result<(), SshClientError> {
    let Some(state) = value.get("state").and_then(Value::as_object) else {
        return Err(protocol_invalid("state reply is missing or malformed"));
    };
    let has_code = state.contains_key("code");
    if !state.contains_key("state")
        || state.len() != if has_code { 2 } else { 1 }
        || (matches!(parsed.state, JobStateKind::Exited) != has_code)
    {
        return Err(protocol_invalid(
            "state reply fields do not match its state",
        ));
    }
    Ok(())
}

fn require_keys(value: &Value, expected: &[&str]) -> Result<(), SshClientError> {
    let Some(object) = value.as_object() else {
        return Err(protocol_invalid("reply must be a JSON object"));
    };
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(protocol_invalid("reply fields are missing or unknown"));
    }
    Ok(())
}

fn validate_returned_status(id: &str, state: &JobState) -> Result<(), SshClientError> {
    validate_id(id)?;
    if matches!(state.state, JobStateKind::Exited) != state.code.is_some() {
        return Err(protocol_invalid("exit code does not match terminal state"));
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), SshClientError> {
    let parsed = uuid::Uuid::parse_str(id)
        .map_err(|_| SshClientError::Invalid("job ID must be a canonical lowercase UUID".into()))?;
    if parsed.to_string() != id {
        return Err(SshClientError::Invalid(
            "job ID must be a canonical lowercase UUID".into(),
        ));
    }
    Ok(())
}

fn validate_spec(spec: &JobSpec) -> Result<(), SshClientError> {
    let program = spec.program.as_str();
    let absolute = std::path::Path::new(program).is_absolute()
        || (program.as_bytes().get(1) == Some(&b':')
            && program
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic))
        || program.starts_with("\\\\");
    if !absolute
        || program.as_bytes().contains(&0)
        || spec.args.iter().any(|arg| arg.as_bytes().contains(&0))
    {
        return Err(SshClientError::Invalid(
            "job program must be an absolute path and arguments must not contain NUL".into(),
        ));
    }
    if let Some(cwd) = &spec.cwd {
        let absolute = std::path::Path::new(cwd).is_absolute()
            || (cwd.as_bytes().get(1) == Some(&b':')
                && cwd.as_bytes().first().is_some_and(u8::is_ascii_alphabetic))
            || cwd.starts_with("\\\\");
        if !absolute || cwd.as_bytes().contains(&0) {
            return Err(SshClientError::Invalid(
                "job working directory must be an absolute path".into(),
            ));
        }
    }
    if spec.source_sha256.len() != 64
        || !spec
            .source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SshClientError::Invalid(
            "job source SHA-256 must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    Ok(())
}

fn protocol_invalid(message: &str) -> SshClientError {
    SshClientError::Invalid(message.to_owned())
}

fn protocol_error(error: ProtocolError) -> SshClientError {
    SshClientError::Invalid(error.to_string())
}

#[cfg(test)]
#[path = "../tests/support/job_client.rs"]
mod tests;
