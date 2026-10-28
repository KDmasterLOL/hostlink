use base64::{Engine as _, engine::general_purpose::STANDARD};
use russh::{ChannelWriteHalf, client::Msg};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

pub(super) const SUBSYSTEM: &str = "hostlink-jobs";
const MAX_OUTPUT_CHUNK_BYTES: usize = 24 * 1024;
pub(super) const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub(super) enum ProtocolError {
    #[error("invalid jobs response: {0}")]
    Invalid(&'static str),
}

use crate::connect::SshClientError;

const CHANNEL_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
use super::{
    model::{JobOutput, JobState, JobStatus, Output},
    validation::validate_id,
};

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
pub(super) struct SealSuccessReply {
    pub(super) ok: bool,
    pub(super) program: String,
    pub(super) sha256: String,
}
pub(super) fn decode_frame(bytes: &[u8]) -> Result<Value, ProtocolError> {
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
    ok: bool,
    error: String,
}

pub(super) fn parse_status(value: Value, expected_id: &str) -> Result<JobStatus, SshClientError> {
    if value.get("ok") == Some(&Value::Bool(false)) {
        return Err(parse_remote_error(value)?);
    }
    require_keys(
        &value,
        &["ok", "id", "state", "data_base64", "next_offset", "eof"],
    )?;
    let reply: SuccessReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("status reply fields are missing or unknown"))?;
    if !reply.ok || reply.id != expected_id {
        return Err(protocol_invalid(
            "status reply success flag, or ID mismatch",
        ));
    }
    if reply.data_base64.is_some() || reply.next_offset.is_some() || reply.eof.is_some() {
        return Err(protocol_invalid("status reply contains output fields"));
    }
    validate_id(&reply.id)?;
    Ok(JobStatus {
        id: reply.id,
        state: reply.state,
    })
}

pub(super) fn parse_output(value: Value, request: &Output) -> Result<JobOutput, SshClientError> {
    if value.get("ok") == Some(&Value::Bool(false)) {
        return Err(parse_remote_error(value)?);
    }
    require_keys(
        &value,
        &["ok", "id", "state", "data_base64", "next_offset", "eof"],
    )?;
    let reply: SuccessReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("output reply fields are missing or unknown"))?;
    if !reply.ok || reply.id != request.id {
        return Err(protocol_invalid(
            "output reply success flag, or ID mismatch",
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
    validate_id(&reply.id)?;
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

pub(super) fn parse_remote_error(value: Value) -> Result<SshClientError, SshClientError> {
    require_keys(&value, &["ok", "error"])?;
    let reply: ErrorReply = serde_json::from_value(value)
        .map_err(|_| protocol_invalid("error reply fields are missing or unknown"))?;
    if reply.ok || reply.error.is_empty() || reply.error.len() > 512 {
        return Err(protocol_invalid("invalid bounded remote error reply"));
    }
    Ok(SshClientError::Invalid(format!(
        "remote jobs error: {}",
        reply.error
    )))
}

pub(super) fn require_keys(value: &Value, expected: &[&str]) -> Result<(), SshClientError> {
    let Some(object) = value.as_object() else {
        return Err(protocol_invalid("reply must be a JSON object"));
    };
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(protocol_invalid("reply fields are missing or unknown"));
    }
    Ok(())
}

pub(super) async fn close_channel(channel: &ChannelWriteHalf<Msg>) {
    let _ = tokio::time::timeout(CHANNEL_CLEANUP_TIMEOUT, channel.close()).await;
}

pub(super) fn protocol_invalid(message: &str) -> SshClientError {
    SshClientError::Invalid(message.to_owned())
}

pub(super) fn protocol_error(error: ProtocolError) -> SshClientError {
    SshClientError::Invalid(error.to_string())
}
