//! Operator-owned, display-only metadata for a stable enrolled machine.

use super::*;
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};

fn validated_label(value: serde_json::Value) -> io::Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| invalid("display_name must be a string or null"))?;
    let label = value.trim();
    if label.is_empty()
        || label.chars().count() > 128
        || label.len() > 512
        || label.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}'
                    | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(invalid(
            "display_name must be 1..=128 printable Unicode characters (max 512 UTF-8 bytes), without controls",
        ));
    }
    Ok(Some(label.to_owned()))
}

pub(super) fn update_display_name_request(
    headers: &HeaderMap,
    app: &App,
    machine_id: &str,
    body: &Bytes,
) -> io::Result<ApiResponse> {
    if let Err(error) = require_operator(headers, app) {
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            &error.to_string(),
        ));
    }
    if let Err(error) = validate_identifier("machine_id", machine_id, 128) {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            &error.to_string(),
        ));
    }
    let input: UpdateDisplayNameRequest = match parse_json_body(body) {
        Ok(input) => input,
        Err(error) => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &error.to_string(),
            ));
        }
    };
    let label = match validated_label(input.display_name) {
        Ok(label) => label,
        Err(error) => {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &error.to_string(),
            ));
        }
    };
    let mut writer = app.lock_state_writer()?;
    let state = writer.state_mut();
    let Some(record) = state.agents.get_mut(machine_id) else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent is not enrolled",
        ));
    };
    if record.display_name != label {
        record.display_name = label;
        if let Err(error) = writer.commit(false) {
            if error.committed() || error.uncertain() {
                return Ok(json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "state_commit_uncertain",
                    "display name publication outcome is uncertain; verify hub inventory before retrying",
                ));
            }
            return Err(error.into_io());
        }
    }
    let state = HubState::load(&app.config.state_file)?;
    let record = state
        .agents
        .get(machine_id)
        .ok_or_else(|| invalid("agent disappeared after display name update"))?;
    hub_audit(
        "agent.display_name.updated",
        HubAuditFields {
            machine_id: Some(record.machine_id.clone()),
            agent_name: Some(record.name.clone()),
            ..HubAuditFields::default()
        },
    );
    Ok(json(
        StatusCode::OK,
        &serde_json::json!({
            "machine_id": record.machine_id,
            "name": record.name,
            "display_name": record.display_name,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_label_validation() {
        assert_eq!(
            validated_label(serde_json::json!("  Тестовый сервер  "))
                .unwrap()
                .as_deref(),
            Some("Тестовый сервер")
        );
        assert_eq!(validated_label(serde_json::Value::Null).unwrap(), None);
        assert!(validated_label(serde_json::json!("")).is_err());
        assert!(validated_label(serde_json::json!("   ")).is_err());
        assert!(validated_label(serde_json::json!("a\nb")).is_err());
        assert!(validated_label(serde_json::json!("a\u{202e}b")).is_err());
        assert!(validated_label(serde_json::json!("a".repeat(129))).is_err());
        assert!(validated_label(serde_json::json!(13)).is_err());
    }
}
