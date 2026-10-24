//! Bounded JSONL control-response framing and protocol validation.

use crate::AppResult;
use crate::error::{protocol_io, protocol_json};
use onec_agent_protocol::{
    AgentRequest, AgentResponse, AgentResponseKind, MAX_CONTROL_LINE_BYTES, PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn write_request(
    writer: &mut (impl AsyncWrite + Unpin),
    request: &AgentRequest,
) -> AppResult<()> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        crate::invalid_config(format!("failed to serialize agent request: {error}"))
    })?;
    if bytes.len() > MAX_CONTROL_LINE_BYTES {
        return Err(crate::protocol_error(
            "agent request exceeds maximum control message size".to_owned(),
        ));
    }
    crate::error::protocol_io(
        "failed to send agent request",
        async {
            writer.write_all(&bytes).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await
        }
        .await,
    )
}

pub(super) async fn read_response_unbuffered(
    reader: &mut (impl AsyncRead + Unpin),
) -> AppResult<AgentResponse> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = protocol_io(
            "failed reading agent response",
            reader.read(&mut byte).await,
        )?;
        if read == 0 {
            return Err(crate::protocol_error(
                "agent connection closed before a response".to_owned(),
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_CONTROL_LINE_BYTES {
            return Err(crate::protocol_error(
                "agent response exceeds maximum control message size".to_owned(),
            ));
        }
    }
    while matches!(line.last(), Some(b'\r')) {
        line.pop();
    }
    let first = line
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if first != Some(b'{') {
        return Err(crate::protocol_error(format!(
            "remote control channel did not return onec-agent JSON ({} bytes, first non-whitespace byte: {}); verify the hub/reverse-listener port and resident onec-agent version",
            line.len(),
            first
                .map(|byte| format!("0x{byte:02x}"))
                .unwrap_or_else(|| "none".to_owned())
        )));
    }
    protocol_json(
        "remote onec-agent returned malformed JSON; verify resident agent/controller compatibility",
        serde_json::from_slice(&line),
    )
}

pub(super) fn response_into_kind(response: AgentResponse) -> AppResult<AgentResponseKind> {
    if response.version != PROTOCOL_VERSION {
        return Err(crate::protocol_error(format!(
            "remote agent protocol version {} is unsupported; expected {}",
            response.version, PROTOCOL_VERSION
        )));
    }
    if !response.ok {
        let code = response
            .error_code
            .map(|code| format!(" [{code}]"))
            .unwrap_or_default();
        return Err(crate::protocol_error(format!(
            "remote agent rejected request{code}: {}",
            response.error.as_deref().unwrap_or("unknown error")
        )));
    }
    response.response.ok_or_else(|| {
        crate::protocol_error("remote agent returned an empty successful response".to_owned())
    })
}

pub(super) fn response_is_path_not_found(response: &AgentResponse) -> bool {
    response.version == PROTOCOL_VERSION
        && !response.ok
        && response.response.is_none()
        && response.error_code == Some(onec_agent_protocol::AgentErrorCode::PathNotFound)
}

pub(super) fn response_is_opaque_failure(response: &AgentResponse) -> bool {
    response.version == PROTOCOL_VERSION
        && !response.ok
        && response.response.is_none()
        && response.error_code.is_none()
}

#[cfg(test)]
mod tests {
    use super::{response_is_opaque_failure, response_is_path_not_found};
    use onec_agent_protocol::{AgentErrorCode, AgentResponse, AgentResponseKind, PROTOCOL_VERSION};

    #[test]
    fn only_explicit_path_not_found_is_a_cache_miss() {
        let proven_missing = AgentResponse::failure_with_code(
            AgentErrorCode::PathNotFound,
            "requested path does not exist",
        );
        let legacy_unknown = AgentResponse::failure("request failed");
        let access_denied =
            AgentResponse::failure_with_code(AgentErrorCode::ExecIoFailed, "access denied");
        assert!(response_is_path_not_found(&proven_missing));
        assert!(!response_is_path_not_found(&legacy_unknown));
        assert!(response_is_opaque_failure(&legacy_unknown));
        assert!(!response_is_path_not_found(&access_denied));
        assert!(!response_is_opaque_failure(&access_denied));
        let mut malformed_failure_with_payload = legacy_unknown.clone();
        malformed_failure_with_payload.response = Some(AgentResponseKind::Hello {
            name: "fixture".to_owned(),
            agent_version: "0.1.1".to_owned(),
            hostname: "fixture".to_owned(),
            os: "windows".to_owned(),
            capabilities: Vec::new(),
            agent_executable: None,
            onec_executable: None,
        });
        assert!(!response_is_opaque_failure(&malformed_failure_with_payload));
        let mut malformed_path_not_found = proven_missing.clone();
        malformed_path_not_found.response = malformed_failure_with_payload.response;
        assert!(!response_is_path_not_found(&malformed_path_not_found));
        let mut unsupported_version = proven_missing.clone();
        unsupported_version.version = PROTOCOL_VERSION + 1;
        assert!(!response_is_path_not_found(&unsupported_version));
        assert!(!response_is_opaque_failure(&unsupported_version));
    }
}
