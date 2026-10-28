use super::{JobState, JobStream, Output, protocol::*};
use serde_json::{Value, json};

const ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA0";

fn status_reply(state: Value) -> Value {
    json!({
        "ok": true, "id": ID, "state": state,
        "data_base64": null, "next_offset": null, "eof": null
    })
}

fn output_reply(state: Value) -> Value {
    let mut reply = status_reply(state);
    reply["data_base64"] = json!("AP8K/w==");
    reply["next_offset"] = json!(4);
    reply["eof"] = json!(true);
    reply
}

fn output_request() -> Output {
    Output {
        id: ID.into(),
        stream: JobStream::Stdout,
        offset: 0,
    }
}

#[test]
fn lifecycle_states_roundtrip_with_exact_agent_wire_shape() {
    use hostlink_agent::jobs::JobState as AgentState;
    for (client, agent, wire) in [
        (
            JobState::Prepared,
            AgentState::Prepared,
            json!({"state": "prepared"}),
        ),
        (
            JobState::Running,
            AgentState::Running,
            json!({"state": "running"}),
        ),
        (
            JobState::Exited { code: 7 },
            AgentState::Exited { code: 7 },
            json!({"state": "exited", "code": 7}),
        ),
        (
            JobState::Failed,
            AgentState::Failed,
            json!({"state": "failed"}),
        ),
        (
            JobState::Interrupted,
            AgentState::Interrupted,
            json!({"state": "interrupted"}),
        ),
    ] {
        assert_eq!(serde_json::to_value(client).unwrap(), wire);
        assert_eq!(serde_json::to_value(agent).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<JobState>(wire.clone()).unwrap(),
            client
        );
        assert_eq!(
            parse_status(status_reply(wire.clone()), ID).unwrap().state,
            client
        );
        let output = parse_output(output_reply(wire), &output_request()).unwrap();
        assert_eq!(output.status.state, client);
        assert_eq!(output.data, [0, 255, 10, 255]);
    }
}

#[test]
fn malformed_states_are_rejected_by_serde_and_both_reply_parsers() {
    let mut states = vec![
        json!({"state": "exited"}),
        json!({"state": "exited", "code": null}),
        json!({"state": "exited", "code": "7"}),
        json!({"state": "exited", "code": 7.5}),
        json!({"state": "exited", "code": 2147483648_i64}),
        json!({"state": "exited", "code": -2147483649_i64}),
        json!({"state": "exited", "code": 7, "extra": true}),
        json!({"code": 7}),
        json!({}),
        json!(null),
        json!("running"),
        json!({"state": 7}),
        json!({"state": "unknown"}),
    ];
    for state in ["prepared", "running", "failed", "interrupted"] {
        states.push(json!({"state": state, "code": 7}));
        states.push(json!({"state": state, "code": null}));
        states.push(json!({"state": state, "extra": true}));
    }
    for state in states {
        assert!(
            serde_json::from_value::<JobState>(state.clone()).is_err(),
            "{state}"
        );
        assert!(
            parse_status(status_reply(state.clone()), ID).is_err(),
            "{state}"
        );
        assert!(
            parse_output(output_reply(state.clone()), &output_request()).is_err(),
            "{state}"
        );
    }
}

#[test]
fn success_envelope_requires_every_key_including_null_output_fields() {
    for mut reply in [
        status_reply(json!({"state": "running"})),
        output_reply(json!({"state": "running"})),
    ] {
        let output = reply["eof"].is_boolean();
        let rejects = |value| {
            if output {
                parse_output(value, &output_request()).is_err()
            } else {
                parse_status(value, ID).is_err()
            }
        };
        for key in ["ok", "id", "state", "data_base64", "next_offset", "eof"] {
            let mut missing = reply.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(rejects(missing), "missing {key}");
        }
        for (key, value) in [
            ("version", json!(2)),
            ("version", json!(null)),
            ("ok", json!(false)),
            ("ok", json!(null)),
            ("id", json!("01ARZ3NDEKTSV4RRFFQ69G5FA1")),
            ("id", json!("550E8400-E29B-41D4-A716-446655440000")),
            ("id", json!("invalid")),
            ("id", json!(null)),
        ] {
            let mut invalid = reply.clone();
            invalid[key] = value;
            assert!(rejects(invalid), "bad {key}");
        }
        reply["unknown"] = json!(true);
        assert!(rejects(reply));
    }
    let noncanonical = "550E8400-E29B-41D4-A716-446655440000";
    let mut reply = status_reply(json!({"state": "running"}));
    reply["id"] = json!(noncanonical);
    assert!(parse_status(reply, noncanonical).is_err());
}

#[test]
fn output_validation_keeps_base64_size_and_exact_offsets() {
    let request = output_request();
    let valid = output_reply(json!({"state": "exited", "code": 7}));
    for (key, value) in [
        ("data_base64", json!("!!!")),
        ("data_base64", json!(null)),
        ("data_base64", json!("AAAA".repeat(8193))),
        ("next_offset", json!(9)),
        ("next_offset", json!(null)),
        ("eof", json!(null)),
    ] {
        let mut reply = valid.clone();
        reply[key] = value;
        assert!(parse_output(reply, &request).is_err(), "{key}");
    }
    let mut overflow = request;
    overflow.offset = u64::MAX;
    assert!(parse_output(valid.clone(), &overflow).is_err());
    assert!(
        parse_status(valid, ID).is_err(),
        "status must reject output data"
    );
}

#[test]
fn remote_errors_require_exact_bounded_envelope() {
    let valid = json!({"ok": false, "error": "unavailable"});
    assert!(parse_remote_error(valid.clone()).is_ok());
    for key in ["ok", "error"] {
        let mut reply = valid.clone();
        reply.as_object_mut().unwrap().remove(key);
        assert!(parse_remote_error(reply).is_err());
    }
    for (key, value) in [
        ("version", json!(2)),
        ("ok", json!(true)),
        ("error", json!("")),
        ("error", json!("x".repeat(513))),
        ("extra", json!(null)),
    ] {
        let mut reply = valid.clone();
        reply[key] = value;
        assert!(parse_remote_error(reply).is_err());
    }
}

use crate::connect::SshClientError;
#[test]
fn only_generic_remote_sftp_failure_can_enter_exact_seal_verification() {
    let failure = || {
        SshClientError::Sftp(russh_sftp::client::error::Error::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: russh_sftp::protocol::StatusCode::Failure,
                error_message: "Failure".into(),
                language_tag: "en-US".into(),
            },
        ))
    };
    let denied = SshClientError::Sftp(russh_sftp::client::error::Error::Status(
        russh_sftp::protocol::Status {
            id: 1,
            status_code: russh_sftp::protocol::StatusCode::PermissionDenied,
            error_message: "Permission denied".into(),
            language_tag: "en-US".into(),
        },
    ));
    assert!(super::upload::sftp_failure_may_be_existing_file(&failure()));
    assert!(!super::upload::sftp_failure_may_be_existing_file(&denied));
    assert!(!super::upload::sftp_failure_may_be_existing_file(
        &SshClientError::Timeout
    ));
}

#[test]
fn caller_ids_require_canonical_ulid_without_overflow_or_uuid_compatibility() {
    for id in [
        "00000000000000000000000000",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ] {
        assert!(super::validate_id(id).is_ok());
    }
    for id in [
        "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "01arz3ndektsv4rrffq69g5fav",
        "01ARZ3NDEKTSV4RRFFQ69G5FAI",
        "550e8400-e29b-41d4-a716-446655440000",
        "../unsafe",
    ] {
        assert!(super::validate_id(id).is_err(), "{id}");
    }
}
